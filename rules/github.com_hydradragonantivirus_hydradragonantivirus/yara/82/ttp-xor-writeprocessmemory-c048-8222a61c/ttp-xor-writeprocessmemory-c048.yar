rule TTP_XOR_WriteProcessMemory_c048 {
  strings:
    $key_c048 = { 97 3a [2] a5 18 [2] a3 2d [2] 8d 2d [2] b2 31 }

  condition:
    any of them
}