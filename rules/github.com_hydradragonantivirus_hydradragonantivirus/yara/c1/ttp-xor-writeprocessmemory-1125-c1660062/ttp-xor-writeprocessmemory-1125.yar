rule TTP_XOR_WriteProcessMemory_1125 {
  strings:
    $key_1125 = { 46 57 [2] 74 75 [2] 72 40 [2] 5c 40 [2] 63 5c }

  condition:
    any of them
}