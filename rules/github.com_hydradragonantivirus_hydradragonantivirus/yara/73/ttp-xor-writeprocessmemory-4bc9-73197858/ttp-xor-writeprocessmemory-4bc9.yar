rule TTP_XOR_WriteProcessMemory_4bc9 {
  strings:
    $key_4bc9 = { 1c bb [2] 2e 99 [2] 28 ac [2] 06 ac [2] 39 b0 }

  condition:
    any of them
}