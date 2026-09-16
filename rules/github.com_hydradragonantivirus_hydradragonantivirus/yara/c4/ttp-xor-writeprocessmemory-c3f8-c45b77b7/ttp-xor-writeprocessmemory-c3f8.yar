rule TTP_XOR_WriteProcessMemory_c3f8 {
  strings:
    $key_c3f8 = { 94 8a [2] a6 a8 [2] a0 9d [2] 8e 9d [2] b1 81 }

  condition:
    any of them
}