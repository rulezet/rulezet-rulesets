rule TTP_XOR_WriteProcessMemory_5778 {
  strings:
    $key_5778 = { 00 0a [2] 32 28 [2] 34 1d [2] 1a 1d [2] 25 01 }

  condition:
    any of them
}