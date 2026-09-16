rule TTP_XOR_QUAD_CurrentVersionRun_b1e0 {
  strings:
    $key_b1e0 = { e2 8f [2] c6 81 [2] ed ad [2] c3 8f [2] d7 94 [2] d8 8e [2] c6 93 [2] c4 92 [2] df 94 [2] c3 93 [2] df bc }

  condition:
    any of them
}