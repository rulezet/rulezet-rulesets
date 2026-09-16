rule TTP_XOR_WriteProcessMemory_c38a {
  strings:
    $key_c38a = { 94 f8 [2] a6 da [2] a0 ef [2] 8e ef [2] b1 f3 }

  condition:
    any of them
}