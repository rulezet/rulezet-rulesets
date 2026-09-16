rule TTP_XOR_WriteProcessMemory_d6f8 {
  strings:
    $key_d6f8 = { 81 8a [2] b3 a8 [2] b5 9d [2] 9b 9d [2] a4 81 }

  condition:
    any of them
}