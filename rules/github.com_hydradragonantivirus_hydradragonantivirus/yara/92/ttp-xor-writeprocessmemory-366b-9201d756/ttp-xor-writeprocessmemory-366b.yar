rule TTP_XOR_WriteProcessMemory_366b {
  strings:
    $key_366b = { 61 19 [2] 53 3b [2] 55 0e [2] 7b 0e [2] 44 12 }

  condition:
    any of them
}