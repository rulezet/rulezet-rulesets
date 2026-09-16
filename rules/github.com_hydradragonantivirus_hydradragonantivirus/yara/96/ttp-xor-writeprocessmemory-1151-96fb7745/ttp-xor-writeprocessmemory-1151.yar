rule TTP_XOR_WriteProcessMemory_1151 {
  strings:
    $key_1151 = { 46 23 [2] 74 01 [2] 72 34 [2] 5c 34 [2] 63 28 }

  condition:
    any of them
}