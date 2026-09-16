rule TTP_XOR_WriteProcessMemory_7768 {
  strings:
    $key_7768 = { 20 1a [2] 12 38 [2] 14 0d [2] 3a 0d [2] 05 11 }

  condition:
    any of them
}