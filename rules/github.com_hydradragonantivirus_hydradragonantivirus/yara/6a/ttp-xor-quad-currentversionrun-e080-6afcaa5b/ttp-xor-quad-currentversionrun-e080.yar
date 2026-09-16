rule TTP_XOR_QUAD_CurrentVersionRun_e080 {
  strings:
    $key_e080 = { b3 ef [2] 97 e1 [2] bc cd [2] 92 ef [2] 86 f4 [2] 89 ee [2] 97 f3 [2] 95 f2 [2] 8e f4 [2] 92 f3 [2] 8e dc }

  condition:
    any of them
}