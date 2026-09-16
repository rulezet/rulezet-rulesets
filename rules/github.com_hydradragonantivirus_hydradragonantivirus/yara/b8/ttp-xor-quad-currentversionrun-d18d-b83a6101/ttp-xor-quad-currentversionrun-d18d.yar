rule TTP_XOR_QUAD_CurrentVersionRun_d18d {
  strings:
    $key_d18d = { 82 e2 [2] a6 ec [2] 8d c0 [2] a3 e2 [2] b7 f9 [2] b8 e3 [2] a6 fe [2] a4 ff [2] bf f9 [2] a3 fe [2] bf d1 }

  condition:
    any of them
}