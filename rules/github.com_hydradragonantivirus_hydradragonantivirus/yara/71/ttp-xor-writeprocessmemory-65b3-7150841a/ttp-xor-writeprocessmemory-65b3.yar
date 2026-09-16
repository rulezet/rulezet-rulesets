rule TTP_XOR_WriteProcessMemory_65b3 {
  strings:
    $key_65b3 = { 32 c1 [2] 00 e3 [2] 06 d6 [2] 28 d6 [2] 17 ca }

  condition:
    any of them
}