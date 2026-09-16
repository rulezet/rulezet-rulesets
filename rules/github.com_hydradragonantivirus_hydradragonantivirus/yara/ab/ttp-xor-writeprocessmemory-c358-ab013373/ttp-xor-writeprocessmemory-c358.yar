rule TTP_XOR_WriteProcessMemory_c358 {
  strings:
    $key_c358 = { 94 2a [2] a6 08 [2] a0 3d [2] 8e 3d [2] b1 21 }

  condition:
    any of them
}