rule TTP_XOR_QUAD_CurrentVersionRun_b1ec {
  strings:
    $key_b1ec = { e2 83 [2] c6 8d [2] ed a1 [2] c3 83 [2] d7 98 [2] d8 82 [2] c6 9f [2] c4 9e [2] df 98 [2] c3 9f [2] df b0 }

  condition:
    any of them
}