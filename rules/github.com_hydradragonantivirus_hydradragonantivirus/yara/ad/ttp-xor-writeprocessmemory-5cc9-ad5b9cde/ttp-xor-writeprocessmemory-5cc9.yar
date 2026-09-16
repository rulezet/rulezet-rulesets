rule TTP_XOR_WriteProcessMemory_5cc9 {
  strings:
    $key_5cc9 = { 0b bb [2] 39 99 [2] 3f ac [2] 11 ac [2] 2e b0 }

  condition:
    any of them
}