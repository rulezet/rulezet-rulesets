rule TTP_XOR_WriteProcessMemory_c16d {
  strings:
    $key_c16d = { 96 1f [2] a4 3d [2] a2 08 [2] 8c 08 [2] b3 14 }

  condition:
    any of them
}