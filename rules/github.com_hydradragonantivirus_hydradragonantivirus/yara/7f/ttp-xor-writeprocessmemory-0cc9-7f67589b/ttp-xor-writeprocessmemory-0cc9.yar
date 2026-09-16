rule TTP_XOR_WriteProcessMemory_0cc9 {
  strings:
    $key_0cc9 = { 5b bb [2] 69 99 [2] 6f ac [2] 41 ac [2] 7e b0 }

  condition:
    any of them
}