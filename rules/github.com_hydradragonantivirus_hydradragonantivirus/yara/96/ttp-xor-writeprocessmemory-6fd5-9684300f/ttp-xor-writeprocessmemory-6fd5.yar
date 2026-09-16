rule TTP_XOR_WriteProcessMemory_6fd5 {
  strings:
    $key_6fd5 = { 38 a7 [2] 0a 85 [2] 0c b0 [2] 22 b0 [2] 1d ac }

  condition:
    any of them
}