rule TTP_XOR_QUAD_CurrentVersionRun_b1f0 {
  strings:
    $key_b1f0 = { e2 9f [2] c6 91 [2] ed bd [2] c3 9f [2] d7 84 [2] d8 9e [2] c6 83 [2] c4 82 [2] df 84 [2] c3 83 [2] df ac }

  condition:
    any of them
}