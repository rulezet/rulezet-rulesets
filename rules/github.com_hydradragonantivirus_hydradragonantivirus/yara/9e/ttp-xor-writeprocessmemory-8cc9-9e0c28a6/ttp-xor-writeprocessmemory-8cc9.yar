rule TTP_XOR_WriteProcessMemory_8cc9 {
  strings:
    $key_8cc9 = { db bb [2] e9 99 [2] ef ac [2] c1 ac [2] fe b0 }

  condition:
    any of them
}