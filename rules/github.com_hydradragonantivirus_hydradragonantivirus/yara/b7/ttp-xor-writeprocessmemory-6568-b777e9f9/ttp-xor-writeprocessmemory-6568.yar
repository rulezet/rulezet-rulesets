rule TTP_XOR_WriteProcessMemory_6568 {
  strings:
    $key_6568 = { 32 1a [2] 00 38 [2] 06 0d [2] 28 0d [2] 17 11 }

  condition:
    any of them
}