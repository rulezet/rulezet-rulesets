rule TTP_XOR_WriteProcessMemory_c78a {
  strings:
    $key_c78a = { 90 f8 [2] a2 da [2] a4 ef [2] 8a ef [2] b5 f3 }

  condition:
    any of them
}