rule TTP_XOR_WriteProcessMemory_c6f8 {
  strings:
    $key_c6f8 = { 91 8a [2] a3 a8 [2] a5 9d [2] 8b 9d [2] b4 81 }

  condition:
    any of them
}