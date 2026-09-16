rule TTP_XOR_WriteProcessMemory_41d6 {
  strings:
    $key_41d6 = { 16 a4 [2] 24 86 [2] 22 b3 [2] 0c b3 [2] 33 af }

  condition:
    any of them
}