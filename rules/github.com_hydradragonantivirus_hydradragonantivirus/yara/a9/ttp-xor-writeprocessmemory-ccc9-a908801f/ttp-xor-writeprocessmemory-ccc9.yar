rule TTP_XOR_WriteProcessMemory_ccc9 {
  strings:
    $key_ccc9 = { 9b bb [2] a9 99 [2] af ac [2] 81 ac [2] be b0 }

  condition:
    any of them
}