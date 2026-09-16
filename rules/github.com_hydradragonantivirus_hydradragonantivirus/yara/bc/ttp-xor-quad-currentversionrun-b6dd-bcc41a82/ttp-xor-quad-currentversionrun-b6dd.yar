rule TTP_XOR_QUAD_CurrentVersionRun_b6dd {
  strings:
    $key_b6dd = { e5 b2 [2] c1 bc [2] ea 90 [2] c4 b2 [2] d0 a9 [2] df b3 [2] c1 ae [2] c3 af [2] d8 a9 [2] c4 ae [2] d8 81 }

  condition:
    any of them
}