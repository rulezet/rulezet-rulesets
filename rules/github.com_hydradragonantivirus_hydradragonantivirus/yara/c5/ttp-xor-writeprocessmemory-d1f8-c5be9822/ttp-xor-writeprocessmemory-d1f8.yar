rule TTP_XOR_WriteProcessMemory_d1f8 {
  strings:
    $key_d1f8 = { 86 8a [2] b4 a8 [2] b2 9d [2] 9c 9d [2] a3 81 }

  condition:
    any of them
}