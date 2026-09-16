rule TTP_XOR_WriteProcessMemory_d248 {
  strings:
    $key_d248 = { 85 3a [2] b7 18 [2] b1 2d [2] 9f 2d [2] a0 31 }

  condition:
    any of them
}