rule TTP_XOR_WriteProcessMemory_d2f8 {
  strings:
    $key_d2f8 = { 85 8a [2] b7 a8 [2] b1 9d [2] 9f 9d [2] a0 81 }

  condition:
    any of them
}