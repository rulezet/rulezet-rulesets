rule TTP_XOR_WriteProcessMemory_0aec {
  strings:
    $key_0aec = { 5d 9e [2] 6f bc [2] 69 89 [2] 47 89 [2] 78 95 }

  condition:
    any of them
}