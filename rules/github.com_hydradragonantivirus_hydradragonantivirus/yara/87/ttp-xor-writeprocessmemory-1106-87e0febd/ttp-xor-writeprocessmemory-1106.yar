rule TTP_XOR_WriteProcessMemory_1106 {
  strings:
    $key_1106 = { 46 74 [2] 74 56 [2] 72 63 [2] 5c 63 [2] 63 7f }

  condition:
    any of them
}