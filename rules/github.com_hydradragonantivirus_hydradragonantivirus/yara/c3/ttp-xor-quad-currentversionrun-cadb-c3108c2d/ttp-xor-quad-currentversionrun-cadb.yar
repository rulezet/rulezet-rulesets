rule TTP_XOR_QUAD_CurrentVersionRun_cadb {
  strings:
    $key_cadb = { 99 b4 [2] bd ba [2] 96 96 [2] b8 b4 [2] ac af [2] a3 b5 [2] bd a8 [2] bf a9 [2] a4 af [2] b8 a8 [2] a4 87 }

  condition:
    any of them
}