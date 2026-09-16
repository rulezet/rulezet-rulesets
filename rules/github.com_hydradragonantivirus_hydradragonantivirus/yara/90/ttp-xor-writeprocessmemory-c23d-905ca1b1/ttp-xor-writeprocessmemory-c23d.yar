rule TTP_XOR_WriteProcessMemory_c23d {
  strings:
    $key_c23d = { 95 4f [2] a7 6d [2] a1 58 [2] 8f 58 [2] b0 44 }

  condition:
    any of them
}