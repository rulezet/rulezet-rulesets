rule TTP_XOR_WriteProcessMemory_c1f8 {
  strings:
    $key_c1f8 = { 96 8a [2] a4 a8 [2] a2 9d [2] 8c 9d [2] b3 81 }

  condition:
    any of them
}