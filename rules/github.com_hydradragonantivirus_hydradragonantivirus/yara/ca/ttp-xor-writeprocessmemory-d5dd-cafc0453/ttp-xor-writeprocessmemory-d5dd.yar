rule TTP_XOR_WriteProcessMemory_d5dd {
  strings:
    $key_d5dd = { 82 af [2] b0 8d [2] b6 b8 [2] 98 b8 [2] a7 a4 }

  condition:
    any of them
}