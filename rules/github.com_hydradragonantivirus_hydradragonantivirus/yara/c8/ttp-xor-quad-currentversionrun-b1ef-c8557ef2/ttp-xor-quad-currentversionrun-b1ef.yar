rule TTP_XOR_QUAD_CurrentVersionRun_b1ef {
  strings:
    $key_b1ef = { e2 80 [2] c6 8e [2] ed a2 [2] c3 80 [2] d7 9b [2] d8 81 [2] c6 9c [2] c4 9d [2] df 9b [2] c3 9c [2] df b3 }

  condition:
    any of them
}