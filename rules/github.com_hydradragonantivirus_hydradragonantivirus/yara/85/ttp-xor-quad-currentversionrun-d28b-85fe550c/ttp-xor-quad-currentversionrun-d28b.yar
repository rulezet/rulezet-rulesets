rule TTP_XOR_QUAD_CurrentVersionRun_d28b {
  strings:
    $key_d28b = { 81 e4 [2] a5 ea [2] 8e c6 [2] a0 e4 [2] b4 ff [2] bb e5 [2] a5 f8 [2] a7 f9 [2] bc ff [2] a0 f8 [2] bc d7 }

  condition:
    any of them
}