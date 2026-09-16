rule TTP_XOR_QUAD_CurrentVersionRun_3080 {
  strings:
    $key_3080 = { 63 ef [2] 47 e1 [2] 6c cd [2] 42 ef [2] 56 f4 [2] 59 ee [2] 47 f3 [2] 45 f2 [2] 5e f4 [2] 42 f3 [2] 5e dc }

  condition:
    any of them
}