rule TTP_XOR_WriteProcessMemory_01d6 {
  strings:
    $key_01d6 = { 56 a4 [2] 64 86 [2] 62 b3 [2] 4c b3 [2] 73 af }

  condition:
    any of them
}