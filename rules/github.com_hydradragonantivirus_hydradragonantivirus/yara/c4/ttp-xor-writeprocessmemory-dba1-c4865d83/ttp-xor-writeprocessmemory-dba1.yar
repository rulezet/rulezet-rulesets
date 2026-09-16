rule TTP_XOR_WriteProcessMemory_dba1 {
  strings:
    $key_dba1 = { 8c d3 [2] be f1 [2] b8 c4 [2] 96 c4 [2] a9 d8 }

  condition:
    any of them
}