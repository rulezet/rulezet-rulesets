rule TTP_XOR_WriteProcessMemory_3bc9 {
  strings:
    $key_3bc9 = { 6c bb [2] 5e 99 [2] 58 ac [2] 76 ac [2] 49 b0 }

  condition:
    any of them
}