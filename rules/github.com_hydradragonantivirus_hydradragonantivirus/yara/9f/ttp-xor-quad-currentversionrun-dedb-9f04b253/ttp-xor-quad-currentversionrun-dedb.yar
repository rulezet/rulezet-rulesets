rule TTP_XOR_QUAD_CurrentVersionRun_dedb {
  strings:
    $key_dedb = { 8d b4 [2] a9 ba [2] 82 96 [2] ac b4 [2] b8 af [2] b7 b5 [2] a9 a8 [2] ab a9 [2] b0 af [2] ac a8 [2] b0 87 }

  condition:
    any of them
}