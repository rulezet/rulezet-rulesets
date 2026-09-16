rule TTP_XOR_WriteProcessMemory_41d4 {
  strings:
    $key_41d4 = { 16 a6 [2] 24 84 [2] 22 b1 [2] 0c b1 [2] 33 ad }

  condition:
    any of them
}