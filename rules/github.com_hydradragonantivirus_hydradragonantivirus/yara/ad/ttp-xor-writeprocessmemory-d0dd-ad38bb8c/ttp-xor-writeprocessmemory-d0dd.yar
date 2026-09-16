rule TTP_XOR_WriteProcessMemory_d0dd {
  strings:
    $key_d0dd = { 87 af [2] b5 8d [2] b3 b8 [2] 9d b8 [2] a2 a4 }

  condition:
    any of them
}