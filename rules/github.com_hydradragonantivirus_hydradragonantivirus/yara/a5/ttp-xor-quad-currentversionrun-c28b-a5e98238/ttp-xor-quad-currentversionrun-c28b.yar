rule TTP_XOR_QUAD_CurrentVersionRun_c28b {
  strings:
    $key_c28b = { 91 e4 [2] b5 ea [2] 9e c6 [2] b0 e4 [2] a4 ff [2] ab e5 [2] b5 f8 [2] b7 f9 [2] ac ff [2] b0 f8 [2] ac d7 }

  condition:
    any of them
}