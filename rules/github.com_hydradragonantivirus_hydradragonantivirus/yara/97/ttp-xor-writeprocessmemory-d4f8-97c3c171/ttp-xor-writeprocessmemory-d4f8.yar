rule TTP_XOR_WriteProcessMemory_d4f8 {
  strings:
    $key_d4f8 = { 83 8a [2] b1 a8 [2] b7 9d [2] 99 9d [2] a6 81 }

  condition:
    any of them
}