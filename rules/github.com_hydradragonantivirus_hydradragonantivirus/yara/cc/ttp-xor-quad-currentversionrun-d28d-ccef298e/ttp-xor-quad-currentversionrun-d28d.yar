rule TTP_XOR_QUAD_CurrentVersionRun_d28d {
  strings:
    $key_d28d = { 81 e2 [2] a5 ec [2] 8e c0 [2] a0 e2 [2] b4 f9 [2] bb e3 [2] a5 fe [2] a7 ff [2] bc f9 [2] a0 fe [2] bc d1 }

  condition:
    any of them
}