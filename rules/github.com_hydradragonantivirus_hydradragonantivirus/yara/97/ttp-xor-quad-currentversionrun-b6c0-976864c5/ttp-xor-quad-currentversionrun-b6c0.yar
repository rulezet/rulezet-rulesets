rule TTP_XOR_QUAD_CurrentVersionRun_b6c0 {
  strings:
    $key_b6c0 = { e5 af [2] c1 a1 [2] ea 8d [2] c4 af [2] d0 b4 [2] df ae [2] c1 b3 [2] c3 b2 [2] d8 b4 [2] c4 b3 [2] d8 9c }

  condition:
    any of them
}