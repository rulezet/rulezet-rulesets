rule TTP_XOR_WriteProcessMemory_c44d {
  strings:
    $key_c44d = { 93 3f [2] a1 1d [2] a7 28 [2] 89 28 [2] b6 34 }

  condition:
    any of them
}