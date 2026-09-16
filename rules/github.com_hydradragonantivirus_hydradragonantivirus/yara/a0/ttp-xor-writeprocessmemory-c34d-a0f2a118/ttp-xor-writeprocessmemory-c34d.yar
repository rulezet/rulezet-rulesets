rule TTP_XOR_WriteProcessMemory_c34d {
  strings:
    $key_c34d = { 94 3f [2] a6 1d [2] a0 28 [2] 8e 28 [2] b1 34 }

  condition:
    any of them
}