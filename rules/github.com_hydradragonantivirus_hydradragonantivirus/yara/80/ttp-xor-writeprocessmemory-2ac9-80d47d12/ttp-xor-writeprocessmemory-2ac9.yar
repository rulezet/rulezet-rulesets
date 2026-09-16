rule TTP_XOR_WriteProcessMemory_2ac9 {
  strings:
    $key_2ac9 = { 7d bb [2] 4f 99 [2] 49 ac [2] 67 ac [2] 58 b0 }

  condition:
    any of them
}