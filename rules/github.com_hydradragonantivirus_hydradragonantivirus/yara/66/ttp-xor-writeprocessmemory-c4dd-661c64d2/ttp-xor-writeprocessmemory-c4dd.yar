rule TTP_XOR_WriteProcessMemory_c4dd {
  strings:
    $key_c4dd = { 93 af [2] a1 8d [2] a7 b8 [2] 89 b8 [2] b6 a4 }

  condition:
    any of them
}