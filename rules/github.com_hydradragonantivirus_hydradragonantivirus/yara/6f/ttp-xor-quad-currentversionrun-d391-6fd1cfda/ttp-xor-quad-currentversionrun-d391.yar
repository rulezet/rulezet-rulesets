rule TTP_XOR_QUAD_CurrentVersionRun_d391 {
  strings:
    $key_d391 = { 80 fe [2] a4 f0 [2] 8f dc [2] a1 fe [2] b5 e5 [2] ba ff [2] a4 e2 [2] a6 e3 [2] bd e5 [2] a1 e2 [2] bd cd }

  condition:
    any of them
}