rule TTP_XOR_QUAD_CurrentVersionRun_d4b8 {
  strings:
    $key_d4b8 = { 87 d7 [2] a3 d9 [2] 88 f5 [2] a6 d7 [2] b2 cc [2] bd d6 [2] a3 cb [2] a1 ca [2] ba cc [2] a6 cb [2] ba e4 }

  condition:
    any of them
}