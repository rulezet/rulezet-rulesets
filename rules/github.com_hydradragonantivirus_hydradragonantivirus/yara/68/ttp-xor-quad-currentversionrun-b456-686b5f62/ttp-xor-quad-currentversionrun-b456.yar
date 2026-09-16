rule TTP_XOR_QUAD_CurrentVersionRun_b456 {
  strings:
    $key_b456 = { e7 39 [2] c3 37 [2] e8 1b [2] c6 39 [2] d2 22 [2] dd 38 [2] c3 25 [2] c1 24 [2] da 22 [2] c6 25 [2] da 0a }

  condition:
    any of them
}