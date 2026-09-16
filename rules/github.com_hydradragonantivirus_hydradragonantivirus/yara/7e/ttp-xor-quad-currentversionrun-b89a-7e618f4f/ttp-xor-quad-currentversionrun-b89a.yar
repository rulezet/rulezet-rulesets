rule TTP_XOR_QUAD_CurrentVersionRun_b89a {
  strings:
    $key_b89a = { eb f5 [2] cf fb [2] e4 d7 [2] ca f5 [2] de ee [2] d1 f4 [2] cf e9 [2] cd e8 [2] d6 ee [2] ca e9 [2] d6 c6 }

  condition:
    any of them
}