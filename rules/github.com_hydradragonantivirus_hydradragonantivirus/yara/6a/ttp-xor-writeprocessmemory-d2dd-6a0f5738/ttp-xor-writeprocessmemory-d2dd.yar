rule TTP_XOR_WriteProcessMemory_d2dd {
  strings:
    $key_d2dd = { 85 af [2] b7 8d [2] b1 b8 [2] 9f b8 [2] a0 a4 }

  condition:
    any of them
}