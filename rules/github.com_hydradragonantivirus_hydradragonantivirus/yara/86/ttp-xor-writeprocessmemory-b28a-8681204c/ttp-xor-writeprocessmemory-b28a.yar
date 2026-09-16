rule TTP_XOR_WriteProcessMemory_b28a {
  strings:
    $key_b28a = { e5 f8 [2] d7 da [2] d1 ef [2] ff ef [2] c0 f3 }

  condition:
    any of them
}