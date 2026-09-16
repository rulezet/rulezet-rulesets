rule TTP_XOR_WriteProcessMemory_1702 {
  strings:
    $key_1702 = { 40 70 [2] 72 52 [2] 74 67 [2] 5a 67 [2] 65 7b }

  condition:
    any of them
}