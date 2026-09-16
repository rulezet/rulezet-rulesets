rule TTP_XOR_WriteProcessMemory_0fd2 {
  strings:
    $key_0fd2 = { 58 a0 [2] 6a 82 [2] 6c b7 [2] 42 b7 [2] 7d ab }

  condition:
    any of them
}