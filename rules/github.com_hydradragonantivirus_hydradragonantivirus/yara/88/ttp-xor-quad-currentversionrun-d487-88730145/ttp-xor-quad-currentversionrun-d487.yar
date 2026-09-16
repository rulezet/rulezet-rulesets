rule TTP_XOR_QUAD_CurrentVersionRun_d487 {
  strings:
    $key_d487 = { 87 e8 [2] a3 e6 [2] 88 ca [2] a6 e8 [2] b2 f3 [2] bd e9 [2] a3 f4 [2] a1 f5 [2] ba f3 [2] a6 f4 [2] ba db }

  condition:
    any of them
}