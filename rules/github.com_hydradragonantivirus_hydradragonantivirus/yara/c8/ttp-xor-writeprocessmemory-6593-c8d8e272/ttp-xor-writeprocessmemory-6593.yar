rule TTP_XOR_WriteProcessMemory_6593 {
  strings:
    $key_6593 = { 32 e1 [2] 00 c3 [2] 06 f6 [2] 28 f6 [2] 17 ea }

  condition:
    any of them
}