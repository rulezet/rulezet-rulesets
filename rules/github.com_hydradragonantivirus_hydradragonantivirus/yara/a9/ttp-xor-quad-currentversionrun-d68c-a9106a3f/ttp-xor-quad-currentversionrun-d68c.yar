rule TTP_XOR_QUAD_CurrentVersionRun_d68c {
  strings:
    $key_d68c = { 85 e3 [2] a1 ed [2] 8a c1 [2] a4 e3 [2] b0 f8 [2] bf e2 [2] a1 ff [2] a3 fe [2] b8 f8 [2] a4 ff [2] b8 d0 }

  condition:
    any of them
}