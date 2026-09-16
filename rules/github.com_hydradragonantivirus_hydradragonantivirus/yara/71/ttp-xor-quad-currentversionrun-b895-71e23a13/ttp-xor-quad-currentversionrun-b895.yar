rule TTP_XOR_QUAD_CurrentVersionRun_b895 {
  strings:
    $key_b895 = { eb fa [2] cf f4 [2] e4 d8 [2] ca fa [2] de e1 [2] d1 fb [2] cf e6 [2] cd e7 [2] d6 e1 [2] ca e6 [2] d6 c9 }

  condition:
    any of them
}