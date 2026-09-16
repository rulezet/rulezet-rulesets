rule TTP_XOR_WriteProcessMemory_00a7 {
  strings:
    $key_00a7 = { 57 d5 [2] 65 f7 [2] 63 c2 [2] 4d c2 [2] 72 de }

  condition:
    any of them
}