rule TTP_XOR_WriteProcessMemory_0fd1 {
  strings:
    $key_0fd1 = { 58 a3 [2] 6a 81 [2] 6c b4 [2] 42 b4 [2] 7d a8 }

  condition:
    any of them
}