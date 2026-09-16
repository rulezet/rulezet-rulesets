rule TTP_XOR_WriteProcessMemory_1743 {
  strings:
    $key_1743 = { 40 31 [2] 72 13 [2] 74 26 [2] 5a 26 [2] 65 3a }

  condition:
    any of them
}