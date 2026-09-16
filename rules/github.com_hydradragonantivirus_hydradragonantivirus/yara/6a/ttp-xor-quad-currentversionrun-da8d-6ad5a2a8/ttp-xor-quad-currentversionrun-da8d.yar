rule TTP_XOR_QUAD_CurrentVersionRun_da8d {
  strings:
    $key_da8d = { 89 e2 [2] ad ec [2] 86 c0 [2] a8 e2 [2] bc f9 [2] b3 e3 [2] ad fe [2] af ff [2] b4 f9 [2] a8 fe [2] b4 d1 }

  condition:
    any of them
}