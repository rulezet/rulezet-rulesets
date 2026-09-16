rule TTP_XOR_QUAD_CurrentVersionRun_c38c {
  strings:
    $key_c38c = { 90 e3 [2] b4 ed [2] 9f c1 [2] b1 e3 [2] a5 f8 [2] aa e2 [2] b4 ff [2] b6 fe [2] ad f8 [2] b1 ff [2] ad d0 }

  condition:
    any of them
}