rule TTP_XOR_QUAD_CurrentVersionRun_1080 {
  strings:
    $key_1080 = { 43 ef [2] 67 e1 [2] 4c cd [2] 62 ef [2] 76 f4 [2] 79 ee [2] 67 f3 [2] 65 f2 [2] 7e f4 [2] 62 f3 [2] 7e dc }

  condition:
    any of them
}