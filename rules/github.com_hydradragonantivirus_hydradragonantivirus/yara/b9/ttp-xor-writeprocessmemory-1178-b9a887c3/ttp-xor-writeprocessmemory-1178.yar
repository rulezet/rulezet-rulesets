rule TTP_XOR_WriteProcessMemory_1178 {
  strings:
    $key_1178 = { 46 0a [2] 74 28 [2] 72 1d [2] 5c 1d [2] 63 01 }

  condition:
    any of them
}