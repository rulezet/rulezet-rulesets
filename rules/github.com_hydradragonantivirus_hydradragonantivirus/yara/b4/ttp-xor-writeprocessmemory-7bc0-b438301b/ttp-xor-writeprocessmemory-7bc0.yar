rule TTP_XOR_WriteProcessMemory_7bc0 {
  strings:
    $key_7bc0 = { 2c b2 [2] 1e 90 [2] 18 a5 [2] 36 a5 [2] 09 b9 }

  condition:
    any of them
}