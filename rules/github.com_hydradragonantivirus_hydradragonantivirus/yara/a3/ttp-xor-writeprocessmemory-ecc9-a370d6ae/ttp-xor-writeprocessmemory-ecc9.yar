rule TTP_XOR_WriteProcessMemory_ecc9 {
  strings:
    $key_ecc9 = { bb bb [2] 89 99 [2] 8f ac [2] a1 ac [2] 9e b0 }

  condition:
    any of them
}