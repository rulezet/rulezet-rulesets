rule TTP_XOR_QUAD_CurrentVersionRun_3480 {
  strings:
    $key_3480 = { 67 ef [2] 43 e1 [2] 68 cd [2] 46 ef [2] 52 f4 [2] 5d ee [2] 43 f3 [2] 41 f2 [2] 5a f4 [2] 46 f3 [2] 5a dc }

  condition:
    any of them
}