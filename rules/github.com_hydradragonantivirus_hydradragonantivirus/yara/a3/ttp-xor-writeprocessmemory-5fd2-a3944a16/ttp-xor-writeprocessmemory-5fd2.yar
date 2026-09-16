rule TTP_XOR_WriteProcessMemory_5fd2 {
  strings:
    $key_5fd2 = { 08 a0 [2] 3a 82 [2] 3c b7 [2] 12 b7 [2] 2d ab }

  condition:
    any of them
}