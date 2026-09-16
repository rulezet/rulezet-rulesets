rule TTP_XOR_WriteProcessMemory_f8c9 {
  strings:
    $key_f8c9 = { af bb [2] 9d 99 [2] 9b ac [2] b5 ac [2] 8a b0 }

  condition:
    any of them
}