rule TTP_XOR_WriteProcessMemory_6565 {
  strings:
    $key_6565 = { 32 17 [2] 00 35 [2] 06 00 [2] 28 00 [2] 17 1c }

  condition:
    any of them
}