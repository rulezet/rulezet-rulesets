rule TTP_XOR_WriteProcessMemory_7bc3 {
  strings:
    $key_7bc3 = { 2c b1 [2] 1e 93 [2] 18 a6 [2] 36 a6 [2] 09 ba }

  condition:
    any of them
}