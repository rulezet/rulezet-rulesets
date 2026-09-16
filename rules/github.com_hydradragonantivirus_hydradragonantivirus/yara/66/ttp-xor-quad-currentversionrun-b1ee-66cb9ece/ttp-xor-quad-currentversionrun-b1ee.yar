rule TTP_XOR_QUAD_CurrentVersionRun_b1ee {
  strings:
    $key_b1ee = { e2 81 [2] c6 8f [2] ed a3 [2] c3 81 [2] d7 9a [2] d8 80 [2] c6 9d [2] c4 9c [2] df 9a [2] c3 9d [2] df b2 }

  condition:
    any of them
}