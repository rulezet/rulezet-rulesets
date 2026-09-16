rule TTP_XOR_WriteProcessMemory_6597 {
  strings:
    $key_6597 = { 32 e5 [2] 00 c7 [2] 06 f2 [2] 28 f2 [2] 17 ee }

  condition:
    any of them
}