rule TTP_XOR_WriteProcessMemory_c3dd {
  strings:
    $key_c3dd = { 94 af [2] a6 8d [2] a0 b8 [2] 8e b8 [2] b1 a4 }

  condition:
    any of them
}