rule TTP_XOR_QUAD_CurrentVersionRun_d48b {
  strings:
    $key_d48b = { 87 e4 [2] a3 ea [2] 88 c6 [2] a6 e4 [2] b2 ff [2] bd e5 [2] a3 f8 [2] a1 f9 [2] ba ff [2] a6 f8 [2] ba d7 }

  condition:
    any of them
}