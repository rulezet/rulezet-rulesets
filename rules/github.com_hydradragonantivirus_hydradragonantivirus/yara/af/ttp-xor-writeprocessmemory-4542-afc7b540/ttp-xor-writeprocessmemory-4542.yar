rule TTP_XOR_WriteProcessMemory_4542 {
  strings:
    $key_4542 = { 12 30 [2] 20 12 [2] 26 27 [2] 08 27 [2] 37 3b }

  condition:
    any of them
}