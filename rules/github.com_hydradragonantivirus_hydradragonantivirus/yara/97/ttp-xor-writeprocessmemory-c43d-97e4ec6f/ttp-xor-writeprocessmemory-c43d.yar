rule TTP_XOR_WriteProcessMemory_c43d {
  strings:
    $key_c43d = { 93 4f [2] a1 6d [2] a7 58 [2] 89 58 [2] b6 44 }

  condition:
    any of them
}