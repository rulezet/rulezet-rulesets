rule TTP_XOR_WriteProcessMemory_1311 {
  strings:
    $key_1311 = { 44 63 [2] 76 41 [2] 70 74 [2] 5e 74 [2] 61 68 }

  condition:
    any of them
}