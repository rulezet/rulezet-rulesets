rule TTP_XOR_QUAD_CurrentVersionRun_ded7 {
  strings:
    $key_ded7 = { 8d b8 [2] a9 b6 [2] 82 9a [2] ac b8 [2] b8 a3 [2] b7 b9 [2] a9 a4 [2] ab a5 [2] b0 a3 [2] ac a4 [2] b0 8b }

  condition:
    any of them
}