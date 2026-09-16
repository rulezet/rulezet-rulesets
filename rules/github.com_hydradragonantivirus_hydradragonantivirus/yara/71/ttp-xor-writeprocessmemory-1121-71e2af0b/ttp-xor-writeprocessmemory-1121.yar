rule TTP_XOR_WriteProcessMemory_1121 {
  strings:
    $key_1121 = { 46 53 [2] 74 71 [2] 72 44 [2] 5c 44 [2] 63 58 }

  condition:
    any of them
}