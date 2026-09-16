rule TTP_XOR_WriteProcessMemory_e4dd {
  strings:
    $key_e4dd = { b3 af [2] 81 8d [2] 87 b8 [2] a9 b8 [2] 96 a4 }

  condition:
    any of them
}