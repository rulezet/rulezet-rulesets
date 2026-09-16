rule TTP_XOR_WriteProcessMemory_6fd2 {
  strings:
    $key_6fd2 = { 38 a0 [2] 0a 82 [2] 0c b7 [2] 22 b7 [2] 1d ab }

  condition:
    any of them
}