rule TTP_XOR_QUAD_CurrentVersionRun_b1a2 {
  strings:
    $key_b1a2 = { e2 cd [2] c6 c3 [2] ed ef [2] c3 cd [2] d7 d6 [2] d8 cc [2] c6 d1 [2] c4 d0 [2] df d6 [2] c3 d1 [2] df fe }

  condition:
    any of them
}