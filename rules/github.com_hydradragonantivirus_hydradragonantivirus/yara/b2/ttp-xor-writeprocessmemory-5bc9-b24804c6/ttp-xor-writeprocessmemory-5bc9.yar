rule TTP_XOR_WriteProcessMemory_5bc9 {
  strings:
    $key_5bc9 = { 0c bb [2] 3e 99 [2] 38 ac [2] 16 ac [2] 29 b0 }

  condition:
    any of them
}