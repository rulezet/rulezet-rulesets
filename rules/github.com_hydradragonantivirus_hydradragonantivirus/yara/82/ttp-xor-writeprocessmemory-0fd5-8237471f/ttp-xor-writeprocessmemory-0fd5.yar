rule TTP_XOR_WriteProcessMemory_0fd5 {
  strings:
    $key_0fd5 = { 58 a7 [2] 6a 85 [2] 6c b0 [2] 42 b0 [2] 7d ac }

  condition:
    any of them
}