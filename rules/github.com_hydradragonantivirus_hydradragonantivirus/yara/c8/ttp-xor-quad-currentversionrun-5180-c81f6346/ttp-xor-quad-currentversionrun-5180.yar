rule TTP_XOR_QUAD_CurrentVersionRun_5180 {
  strings:
    $key_5180 = { 02 ef [2] 26 e1 [2] 0d cd [2] 23 ef [2] 37 f4 [2] 38 ee [2] 26 f3 [2] 24 f2 [2] 3f f4 [2] 23 f3 [2] 3f dc }

  condition:
    any of them
}