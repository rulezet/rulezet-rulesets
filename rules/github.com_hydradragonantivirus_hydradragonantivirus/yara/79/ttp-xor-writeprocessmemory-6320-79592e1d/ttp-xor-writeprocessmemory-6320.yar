rule TTP_XOR_WriteProcessMemory_6320 {
  strings:
    $key_6320 = { 34 52 [2] 06 70 [2] 00 45 [2] 2e 45 [2] 11 59 }

  condition:
    any of them
}