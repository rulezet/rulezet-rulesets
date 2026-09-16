rule TTP_XOR_WriteProcessMemory_2515 {
  strings:
    $key_2515 = { 72 67 [2] 40 45 [2] 46 70 [2] 68 70 [2] 57 6c }

  condition:
    any of them
}