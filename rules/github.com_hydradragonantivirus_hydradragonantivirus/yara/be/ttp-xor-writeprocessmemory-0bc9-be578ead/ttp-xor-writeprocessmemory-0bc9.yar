rule TTP_XOR_WriteProcessMemory_0bc9 {
  strings:
    $key_0bc9 = { 5c bb [2] 6e 99 [2] 68 ac [2] 46 ac [2] 79 b0 }

  condition:
    any of them
}