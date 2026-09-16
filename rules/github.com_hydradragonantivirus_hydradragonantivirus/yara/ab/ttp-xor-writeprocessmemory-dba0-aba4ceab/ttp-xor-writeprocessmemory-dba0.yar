rule TTP_XOR_WriteProcessMemory_dba0 {
  strings:
    $key_dba0 = { 8c d2 [2] be f0 [2] b8 c5 [2] 96 c5 [2] a9 d9 }

  condition:
    any of them
}