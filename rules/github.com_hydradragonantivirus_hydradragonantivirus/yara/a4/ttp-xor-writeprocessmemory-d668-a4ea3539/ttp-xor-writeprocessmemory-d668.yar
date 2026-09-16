rule TTP_XOR_WriteProcessMemory_d668 {
  strings:
    $key_d668 = { 81 1a [2] b3 38 [2] b5 0d [2] 9b 0d [2] a4 11 }

  condition:
    any of them
}