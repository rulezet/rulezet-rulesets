rule TTP_XOR_WriteProcessMemory_6515 {
  strings:
    $key_6515 = { 32 67 [2] 00 45 [2] 06 70 [2] 28 70 [2] 17 6c }

  condition:
    any of them
}