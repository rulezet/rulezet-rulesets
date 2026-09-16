rule TTP_XOR_WriteProcessMemory_daec {
  strings:
    $key_daec = { 8d 9e [2] bf bc [2] b9 89 [2] 97 89 [2] a8 95 }

  condition:
    any of them
}