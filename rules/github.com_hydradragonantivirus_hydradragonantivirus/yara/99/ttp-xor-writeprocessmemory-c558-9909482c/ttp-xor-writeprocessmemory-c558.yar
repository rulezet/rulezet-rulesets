rule TTP_XOR_WriteProcessMemory_c558 {
  strings:
    $key_c558 = { 92 2a [2] a0 08 [2] a6 3d [2] 88 3d [2] b7 21 }

  condition:
    any of them
}