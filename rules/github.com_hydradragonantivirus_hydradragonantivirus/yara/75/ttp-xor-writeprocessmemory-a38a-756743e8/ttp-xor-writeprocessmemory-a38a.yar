rule TTP_XOR_WriteProcessMemory_a38a {
  strings:
    $key_a38a = { f4 f8 [2] c6 da [2] c0 ef [2] ee ef [2] d1 f3 }

  condition:
    any of them
}