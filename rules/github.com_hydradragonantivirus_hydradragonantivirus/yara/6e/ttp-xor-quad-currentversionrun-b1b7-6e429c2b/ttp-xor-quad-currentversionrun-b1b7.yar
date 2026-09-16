rule TTP_XOR_QUAD_CurrentVersionRun_b1b7 {
  strings:
    $key_b1b7 = { e2 d8 [2] c6 d6 [2] ed fa [2] c3 d8 [2] d7 c3 [2] d8 d9 [2] c6 c4 [2] c4 c5 [2] df c3 [2] c3 c4 [2] df eb }

  condition:
    any of them
}