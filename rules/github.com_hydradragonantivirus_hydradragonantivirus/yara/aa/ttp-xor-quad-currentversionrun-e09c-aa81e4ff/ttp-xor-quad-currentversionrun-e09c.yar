rule TTP_XOR_QUAD_CurrentVersionRun_e09c {
  strings:
    $key_e09c = { b3 f3 [2] 97 fd [2] bc d1 [2] 92 f3 [2] 86 e8 [2] 89 f2 [2] 97 ef [2] 95 ee [2] 8e e8 [2] 92 ef [2] 8e c0 }

  condition:
    any of them
}