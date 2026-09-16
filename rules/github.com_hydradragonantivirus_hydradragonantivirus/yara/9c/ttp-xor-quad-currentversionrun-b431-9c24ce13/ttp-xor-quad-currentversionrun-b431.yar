rule TTP_XOR_QUAD_CurrentVersionRun_b431 {
  strings:
    $key_b431 = { e7 5e [2] c3 50 [2] e8 7c [2] c6 5e [2] d2 45 [2] dd 5f [2] c3 42 [2] c1 43 [2] da 45 [2] c6 42 [2] da 6d }

  condition:
    any of them
}