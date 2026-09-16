rule TTP_XOR_WriteProcessMemory_ebc9 {
  strings:
    $key_ebc9 = { bc bb [2] 8e 99 [2] 88 ac [2] a6 ac [2] 99 b0 }

  condition:
    any of them
}