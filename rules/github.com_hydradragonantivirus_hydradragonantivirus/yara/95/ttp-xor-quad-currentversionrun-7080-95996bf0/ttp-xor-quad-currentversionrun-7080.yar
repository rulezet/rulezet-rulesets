rule TTP_XOR_QUAD_CurrentVersionRun_7080 {
  strings:
    $key_7080 = { 23 ef [2] 07 e1 [2] 2c cd [2] 02 ef [2] 16 f4 [2] 19 ee [2] 07 f3 [2] 05 f2 [2] 1e f4 [2] 02 f3 [2] 1e dc }

  condition:
    any of them
}