rule TTP_XOR_QUAD_CurrentVersionRun_d58b {
  strings:
    $key_d58b = { 86 e4 [2] a2 ea [2] 89 c6 [2] a7 e4 [2] b3 ff [2] bc e5 [2] a2 f8 [2] a0 f9 [2] bb ff [2] a7 f8 [2] bb d7 }

  condition:
    any of them
}