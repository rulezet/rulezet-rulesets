rule TTP_XOR_WriteProcessMemory_7668 {
  strings:
    $key_7668 = { 21 1a [2] 13 38 [2] 15 0d [2] 3b 0d [2] 04 11 }

  condition:
    any of them
}