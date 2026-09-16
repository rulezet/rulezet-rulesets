rule TTP_XOR_WriteProcessMemory_f4c9 {
  strings:
    $key_f4c9 = { a3 bb [2] 91 99 [2] 97 ac [2] b9 ac [2] 86 b0 }

  condition:
    any of them
}