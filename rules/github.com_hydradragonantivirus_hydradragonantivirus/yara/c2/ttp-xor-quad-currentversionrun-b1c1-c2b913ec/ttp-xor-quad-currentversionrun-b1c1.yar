rule TTP_XOR_QUAD_CurrentVersionRun_b1c1 {
  strings:
    $key_b1c1 = { e2 ae [2] c6 a0 [2] ed 8c [2] c3 ae [2] d7 b5 [2] d8 af [2] c6 b2 [2] c4 b3 [2] df b5 [2] c3 b2 [2] df 9d }

  condition:
    any of them
}