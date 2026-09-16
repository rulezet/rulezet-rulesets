rule TTP_XOR_WriteProcessMemory_5aec {
  strings:
    $key_5aec = { 0d 9e [2] 3f bc [2] 39 89 [2] 17 89 [2] 28 95 }

  condition:
    any of them
}