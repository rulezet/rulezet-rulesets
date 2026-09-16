rule TTP_XOR_WriteProcessMemory_1315 {
  strings:
    $key_1315 = { 44 67 [2] 76 45 [2] 70 70 [2] 5e 70 [2] 61 6c }

  condition:
    any of them
}