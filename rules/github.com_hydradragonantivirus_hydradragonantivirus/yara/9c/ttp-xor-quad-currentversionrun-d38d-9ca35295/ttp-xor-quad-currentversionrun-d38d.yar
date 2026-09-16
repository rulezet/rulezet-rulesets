rule TTP_XOR_QUAD_CurrentVersionRun_d38d {
  strings:
    $key_d38d = { 80 e2 [2] a4 ec [2] 8f c0 [2] a1 e2 [2] b5 f9 [2] ba e3 [2] a4 fe [2] a6 ff [2] bd f9 [2] a1 fe [2] bd d1 }

  condition:
    any of them
}