rule TTP_XOR_WriteProcessMemory_dbe0 {
  strings:
    $key_dbe0 = { 8c 92 [2] be b0 [2] b8 85 [2] 96 85 [2] a9 99 }

  condition:
    any of them
}