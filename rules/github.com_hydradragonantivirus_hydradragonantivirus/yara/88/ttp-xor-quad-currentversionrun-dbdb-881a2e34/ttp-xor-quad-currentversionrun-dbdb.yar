rule TTP_XOR_QUAD_CurrentVersionRun_dbdb {
  strings:
    $key_dbdb = { 88 b4 [2] ac ba [2] 87 96 [2] a9 b4 [2] bd af [2] b2 b5 [2] ac a8 [2] ae a9 [2] b5 af [2] a9 a8 [2] b5 87 }

  condition:
    any of them
}