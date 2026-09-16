rule TTP_XOR_WriteProcessMemory_7bc9 {
  strings:
    $key_7bc9 = { 2c bb [2] 1e 99 [2] 18 ac [2] 36 ac [2] 09 b0 }

  condition:
    any of them
}