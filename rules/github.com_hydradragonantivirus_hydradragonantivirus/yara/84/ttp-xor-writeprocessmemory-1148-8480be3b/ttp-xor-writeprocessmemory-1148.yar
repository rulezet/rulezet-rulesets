rule TTP_XOR_WriteProcessMemory_1148 {
  strings:
    $key_1148 = { 46 3a [2] 74 18 [2] 72 2d [2] 5c 2d [2] 63 31 }

  condition:
    any of them
}