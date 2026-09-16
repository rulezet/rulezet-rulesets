rule TTP_XOR_WriteProcessMemory_1160 {
  strings:
    $key_1160 = { 46 12 [2] 74 30 [2] 72 05 [2] 5c 05 [2] 63 19 }

  condition:
    any of them
}