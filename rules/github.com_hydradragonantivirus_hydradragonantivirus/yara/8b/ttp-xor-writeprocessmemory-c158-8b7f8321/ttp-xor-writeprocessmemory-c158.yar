rule TTP_XOR_WriteProcessMemory_c158 {
  strings:
    $key_c158 = { 96 2a [2] a4 08 [2] a2 3d [2] 8c 3d [2] b3 21 }

  condition:
    any of them
}