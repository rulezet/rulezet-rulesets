rule TTP_XOR_WriteProcessMemory_6bc9 {
  strings:
    $key_6bc9 = { 3c bb [2] 0e 99 [2] 08 ac [2] 26 ac [2] 19 b0 }

  condition:
    any of them
}