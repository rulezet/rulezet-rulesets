rule TTP_XOR_WriteProcessMemory_7bc5 {
  strings:
    $key_7bc5 = { 2c b7 [2] 1e 95 [2] 18 a0 [2] 36 a0 [2] 09 bc }

  condition:
    any of them
}