rule TTP_XOR_WriteProcessMemory_3ac9 {
  strings:
    $key_3ac9 = { 6d bb [2] 5f 99 [2] 59 ac [2] 77 ac [2] 48 b0 }

  condition:
    any of them
}