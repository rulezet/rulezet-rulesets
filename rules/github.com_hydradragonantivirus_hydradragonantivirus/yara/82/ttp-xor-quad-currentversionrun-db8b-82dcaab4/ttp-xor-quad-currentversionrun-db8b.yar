rule TTP_XOR_QUAD_CurrentVersionRun_db8b {
  strings:
    $key_db8b = { 88 e4 [2] ac ea [2] 87 c6 [2] a9 e4 [2] bd ff [2] b2 e5 [2] ac f8 [2] ae f9 [2] b5 ff [2] a9 f8 [2] b5 d7 }

  condition:
    any of them
}