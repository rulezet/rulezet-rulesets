rule TTP_XOR_WriteProcessMemory_d7f8 {
  strings:
    $key_d7f8 = { 80 8a [2] b2 a8 [2] b4 9d [2] 9a 9d [2] a5 81 }

  condition:
    any of them
}