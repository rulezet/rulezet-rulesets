rule TTP_XOR_WriteProcessMemory_c26d {
  strings:
    $key_c26d = { 95 1f [2] a7 3d [2] a1 08 [2] 8f 08 [2] b0 14 }

  condition:
    any of them
}