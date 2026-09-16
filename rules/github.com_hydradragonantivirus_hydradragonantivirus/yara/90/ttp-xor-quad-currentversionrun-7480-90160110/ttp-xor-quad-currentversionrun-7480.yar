rule TTP_XOR_QUAD_CurrentVersionRun_7480 {
  strings:
    $key_7480 = { 27 ef [2] 03 e1 [2] 28 cd [2] 06 ef [2] 12 f4 [2] 1d ee [2] 03 f3 [2] 01 f2 [2] 1a f4 [2] 06 f3 [2] 1a dc }

  condition:
    any of them
}