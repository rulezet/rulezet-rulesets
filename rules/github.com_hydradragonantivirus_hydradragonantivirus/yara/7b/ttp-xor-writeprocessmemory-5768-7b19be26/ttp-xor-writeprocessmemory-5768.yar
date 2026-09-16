rule TTP_XOR_WriteProcessMemory_5768 {
  strings:
    $key_5768 = { 00 1a [2] 32 38 [2] 34 0d [2] 1a 0d [2] 25 11 }

  condition:
    any of them
}