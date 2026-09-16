rule TTP_XOR_QUAD_CurrentVersionRun_c78d {
  strings:
    $key_c78d = { 94 e2 [2] b0 ec [2] 9b c0 [2] b5 e2 [2] a1 f9 [2] ae e3 [2] b0 fe [2] b2 ff [2] a9 f9 [2] b5 fe [2] a9 d1 }

  condition:
    any of them
}