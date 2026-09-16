rule TTP_XOR_WriteProcessMemory_65f1 {
  strings:
    $key_65f1 = { 32 83 [2] 00 a1 [2] 06 94 [2] 28 94 [2] 17 88 }

  condition:
    any of them
}