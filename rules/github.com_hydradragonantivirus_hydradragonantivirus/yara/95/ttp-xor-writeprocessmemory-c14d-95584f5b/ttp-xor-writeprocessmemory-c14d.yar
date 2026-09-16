rule TTP_XOR_WriteProcessMemory_c14d {
  strings:
    $key_c14d = { 96 3f [2] a4 1d [2] a2 28 [2] 8c 28 [2] b3 34 }

  condition:
    any of them
}