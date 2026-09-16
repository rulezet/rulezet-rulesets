rule TTP_XOR_QUAD_CurrentVersionRun_c38d {
  strings:
    $key_c38d = { 90 e2 [2] b4 ec [2] 9f c0 [2] b1 e2 [2] a5 f9 [2] aa e3 [2] b4 fe [2] b6 ff [2] ad f9 [2] b1 fe [2] ad d1 }

  condition:
    any of them
}