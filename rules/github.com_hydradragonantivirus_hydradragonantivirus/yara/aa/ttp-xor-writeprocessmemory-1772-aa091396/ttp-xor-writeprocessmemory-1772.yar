rule TTP_XOR_WriteProcessMemory_1772 {
  strings:
    $key_1772 = { 40 00 [2] 72 22 [2] 74 17 [2] 5a 17 [2] 65 0b }

  condition:
    any of them
}