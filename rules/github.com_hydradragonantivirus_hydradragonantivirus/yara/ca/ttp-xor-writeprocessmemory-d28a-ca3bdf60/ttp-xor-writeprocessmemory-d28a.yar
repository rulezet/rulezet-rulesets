rule TTP_XOR_WriteProcessMemory_d28a {
  strings:
    $key_d28a = { 85 f8 [2] b7 da [2] b1 ef [2] 9f ef [2] a0 f3 }

  condition:
    any of them
}