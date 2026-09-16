rule TTP_XOR_WriteProcessMemory_c5f8 {
  strings:
    $key_c5f8 = { 92 8a [2] a0 a8 [2] a6 9d [2] 88 9d [2] b7 81 }

  condition:
    any of them
}