rule TTP_XOR_QUAD_CurrentVersionRun_ce9f {
  strings:
    $key_ce9f = { 9d f0 [2] b9 fe [2] 92 d2 [2] bc f0 [2] a8 eb [2] a7 f1 [2] b9 ec [2] bb ed [2] a0 eb [2] bc ec [2] a0 c3 }

  condition:
    any of them
}