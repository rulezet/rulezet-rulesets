rule TTP_XOR_WriteProcessMemory_7ac9 {
  strings:
    $key_7ac9 = { 2d bb [2] 1f 99 [2] 19 ac [2] 37 ac [2] 08 b0 }

  condition:
    any of them
}