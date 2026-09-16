rule TTP_XOR_WriteProcessMemory_65c4 {
  strings:
    $key_65c4 = { 32 b6 [2] 00 94 [2] 06 a1 [2] 28 a1 [2] 17 bd }

  condition:
    any of them
}