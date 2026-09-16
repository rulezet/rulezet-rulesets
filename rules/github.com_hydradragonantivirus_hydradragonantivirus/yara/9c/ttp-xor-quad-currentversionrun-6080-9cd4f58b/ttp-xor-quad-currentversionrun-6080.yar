rule TTP_XOR_QUAD_CurrentVersionRun_6080 {
  strings:
    $key_6080 = { 33 ef [2] 17 e1 [2] 3c cd [2] 12 ef [2] 06 f4 [2] 09 ee [2] 17 f3 [2] 15 f2 [2] 0e f4 [2] 12 f3 [2] 0e dc }

  condition:
    any of them
}