rule TTP_XOR_WriteProcessMemory_1732 {
  strings:
    $key_1732 = { 40 40 [2] 72 62 [2] 74 57 [2] 5a 57 [2] 65 4b }

  condition:
    any of them
}