rule TTP_XOR_WriteProcessMemory_1168 {
  strings:
    $key_1168 = { 46 1a [2] 74 38 [2] 72 0d [2] 5c 0d [2] 63 11 }

  condition:
    any of them
}