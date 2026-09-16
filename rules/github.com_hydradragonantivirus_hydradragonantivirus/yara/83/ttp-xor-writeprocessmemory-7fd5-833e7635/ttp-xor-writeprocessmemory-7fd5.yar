rule TTP_XOR_WriteProcessMemory_7fd5 {
  strings:
    $key_7fd5 = { 28 a7 [2] 1a 85 [2] 1c b0 [2] 32 b0 [2] 0d ac }

  condition:
    any of them
}