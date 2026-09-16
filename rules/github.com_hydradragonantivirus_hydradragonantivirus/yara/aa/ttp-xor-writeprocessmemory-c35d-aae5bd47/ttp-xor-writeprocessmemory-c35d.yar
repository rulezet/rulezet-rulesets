rule TTP_XOR_WriteProcessMemory_c35d {
  strings:
    $key_c35d = { 94 2f [2] a6 0d [2] a0 38 [2] 8e 38 [2] b1 24 }

  condition:
    any of them
}