rule TTP_XOR_QUAD_CurrentVersionRun_ded6 {
  strings:
    $key_ded6 = { 8d b9 [2] a9 b7 [2] 82 9b [2] ac b9 [2] b8 a2 [2] b7 b8 [2] a9 a5 [2] ab a4 [2] b0 a2 [2] ac a5 [2] b0 8a }

  condition:
    any of them
}