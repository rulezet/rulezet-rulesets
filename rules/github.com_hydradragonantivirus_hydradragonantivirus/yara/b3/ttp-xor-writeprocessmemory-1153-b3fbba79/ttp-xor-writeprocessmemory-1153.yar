rule TTP_XOR_WriteProcessMemory_1153 {
  strings:
    $key_1153 = { 46 21 [2] 74 03 [2] 72 36 [2] 5c 36 [2] 63 2a }

  condition:
    any of them
}