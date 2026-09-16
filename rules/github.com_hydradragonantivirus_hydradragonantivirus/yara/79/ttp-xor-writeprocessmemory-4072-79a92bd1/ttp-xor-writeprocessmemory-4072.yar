rule TTP_XOR_WriteProcessMemory_4072 {
  strings:
    $key_4072 = { 17 00 [2] 25 22 [2] 23 17 [2] 0d 17 [2] 32 0b }

  condition:
    any of them
}