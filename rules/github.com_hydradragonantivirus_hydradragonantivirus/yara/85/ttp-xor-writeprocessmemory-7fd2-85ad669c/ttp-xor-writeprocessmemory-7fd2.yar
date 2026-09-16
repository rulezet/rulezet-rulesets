rule TTP_XOR_WriteProcessMemory_7fd2 {
  strings:
    $key_7fd2 = { 28 a0 [2] 1a 82 [2] 1c b7 [2] 32 b7 [2] 0d ab }

  condition:
    any of them
}