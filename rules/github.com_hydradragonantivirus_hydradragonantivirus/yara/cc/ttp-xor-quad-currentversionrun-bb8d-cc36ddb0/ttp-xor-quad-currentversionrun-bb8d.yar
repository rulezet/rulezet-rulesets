rule TTP_XOR_QUAD_CurrentVersionRun_bb8d {
  strings:
    $key_bb8d = { e8 e2 [2] cc ec [2] e7 c0 [2] c9 e2 [2] dd f9 [2] d2 e3 [2] cc fe [2] ce ff [2] d5 f9 [2] c9 fe [2] d5 d1 }

  condition:
    any of them
}