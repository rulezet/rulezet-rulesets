rule TTP_XOR_WriteProcessMemory_7778 {
  strings:
    $key_7778 = { 20 0a [2] 12 28 [2] 14 1d [2] 3a 1d [2] 05 01 }

  condition:
    any of them
}