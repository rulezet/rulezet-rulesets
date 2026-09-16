rule TTP_XOR_WriteProcessMemory_6580 {
  strings:
    $key_6580 = { 32 f2 [2] 00 d0 [2] 06 e5 [2] 28 e5 [2] 17 f9 }

  condition:
    any of them
}