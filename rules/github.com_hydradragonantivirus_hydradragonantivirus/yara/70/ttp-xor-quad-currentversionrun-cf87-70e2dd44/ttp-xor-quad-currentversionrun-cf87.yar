rule TTP_XOR_QUAD_CurrentVersionRun_cf87 {
  strings:
    $key_cf87 = { 9c e8 [2] b8 e6 [2] 93 ca [2] bd e8 [2] a9 f3 [2] a6 e9 [2] b8 f4 [2] ba f5 [2] a1 f3 [2] bd f4 [2] a1 db }

  condition:
    any of them
}