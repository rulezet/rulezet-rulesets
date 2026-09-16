rule TTP_XOR_WriteProcessMemory_6cc9 {
  strings:
    $key_6cc9 = { 3b bb [2] 09 99 [2] 0f ac [2] 21 ac [2] 1e b0 }

  condition:
    any of them
}