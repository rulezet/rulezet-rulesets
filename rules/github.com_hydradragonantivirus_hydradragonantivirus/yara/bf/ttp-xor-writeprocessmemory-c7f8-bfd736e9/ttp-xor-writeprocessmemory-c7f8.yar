rule TTP_XOR_WriteProcessMemory_c7f8 {
  strings:
    $key_c7f8 = { 90 8a [2] a2 a8 [2] a4 9d [2] 8a 9d [2] b5 81 }

  condition:
    any of them
}