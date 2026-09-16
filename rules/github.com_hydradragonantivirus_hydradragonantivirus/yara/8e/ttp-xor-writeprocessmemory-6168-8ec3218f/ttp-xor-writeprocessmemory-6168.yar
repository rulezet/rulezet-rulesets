rule TTP_XOR_WriteProcessMemory_6168 {
  strings:
    $key_6168 = { 36 1a [2] 04 38 [2] 02 0d [2] 2c 0d [2] 13 11 }

  condition:
    any of them
}