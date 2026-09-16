rule TTP_XOR_WriteProcessMemory_1122 {
  strings:
    $key_1122 = { 46 50 [2] 74 72 [2] 72 47 [2] 5c 47 [2] 63 5b }

  condition:
    any of them
}