rule TTP_XOR_WriteProcessMemory_1704 {
  strings:
    $key_1704 = { 40 76 [2] 72 54 [2] 74 61 [2] 5a 61 [2] 65 7d }

  condition:
    any of them
}