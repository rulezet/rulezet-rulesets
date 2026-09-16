rule TTP_XOR_WriteProcessMemory_1171 {
  strings:
    $key_1171 = { 46 03 [2] 74 21 [2] 72 14 [2] 5c 14 [2] 63 08 }

  condition:
    any of them
}