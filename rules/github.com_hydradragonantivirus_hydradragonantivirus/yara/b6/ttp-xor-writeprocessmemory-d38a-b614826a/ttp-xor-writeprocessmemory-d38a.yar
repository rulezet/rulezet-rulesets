rule TTP_XOR_WriteProcessMemory_d38a {
  strings:
    $key_d38a = { 84 f8 [2] b6 da [2] b0 ef [2] 9e ef [2] a1 f3 }

  condition:
    any of them
}