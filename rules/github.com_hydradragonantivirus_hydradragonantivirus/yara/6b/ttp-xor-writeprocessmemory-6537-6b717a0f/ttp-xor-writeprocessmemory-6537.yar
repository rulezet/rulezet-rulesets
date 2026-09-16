rule TTP_XOR_WriteProcessMemory_6537 {
  strings:
    $key_6537 = { 32 45 [2] 00 67 [2] 06 52 [2] 28 52 [2] 17 4e }

  condition:
    any of them
}