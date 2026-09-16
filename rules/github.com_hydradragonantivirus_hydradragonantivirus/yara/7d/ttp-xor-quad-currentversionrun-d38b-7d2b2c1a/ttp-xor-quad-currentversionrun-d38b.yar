rule TTP_XOR_QUAD_CurrentVersionRun_d38b {
  strings:
    $key_d38b = { 80 e4 [2] a4 ea [2] 8f c6 [2] a1 e4 [2] b5 ff [2] ba e5 [2] a4 f8 [2] a6 f9 [2] bd ff [2] a1 f8 [2] bd d7 }

  condition:
    any of them
}