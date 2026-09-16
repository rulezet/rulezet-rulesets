rule TTP_XOR_WriteProcessMemory_1102 {
  strings:
    $key_1102 = { 46 70 [2] 74 52 [2] 72 67 [2] 5c 67 [2] 63 7b }

  condition:
    any of them
}