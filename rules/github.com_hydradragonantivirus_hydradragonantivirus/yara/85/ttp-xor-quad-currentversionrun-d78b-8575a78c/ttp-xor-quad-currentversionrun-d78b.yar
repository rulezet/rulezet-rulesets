rule TTP_XOR_QUAD_CurrentVersionRun_d78b {
  strings:
    $key_d78b = { 84 e4 [2] a0 ea [2] 8b c6 [2] a5 e4 [2] b1 ff [2] be e5 [2] a0 f8 [2] a2 f9 [2] b9 ff [2] a5 f8 [2] b9 d7 }

  condition:
    any of them
}