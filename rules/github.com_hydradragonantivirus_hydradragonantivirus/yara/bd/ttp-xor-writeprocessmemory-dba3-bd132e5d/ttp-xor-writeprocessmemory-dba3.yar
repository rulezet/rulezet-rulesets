rule TTP_XOR_WriteProcessMemory_dba3 {
  strings:
    $key_dba3 = { 8c d1 [2] be f3 [2] b8 c6 [2] 96 c6 [2] a9 da }

  condition:
    any of them
}