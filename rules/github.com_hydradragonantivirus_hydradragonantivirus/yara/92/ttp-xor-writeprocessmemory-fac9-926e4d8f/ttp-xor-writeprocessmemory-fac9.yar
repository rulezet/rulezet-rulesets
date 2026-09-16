rule TTP_XOR_WriteProcessMemory_fac9 {
  strings:
    $key_fac9 = { ad bb [2] 9f 99 [2] 99 ac [2] b7 ac [2] 88 b0 }

  condition:
    any of them
}