rule TTP_XOR_WriteProcessMemory_c76d {
  strings:
    $key_c76d = { 90 1f [2] a2 3d [2] a4 08 [2] 8a 08 [2] b5 14 }

  condition:
    any of them
}