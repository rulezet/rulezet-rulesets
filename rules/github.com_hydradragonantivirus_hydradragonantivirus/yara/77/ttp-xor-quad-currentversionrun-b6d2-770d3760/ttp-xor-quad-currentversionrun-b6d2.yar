rule TTP_XOR_QUAD_CurrentVersionRun_b6d2 {
  strings:
    $key_b6d2 = { e5 bd [2] c1 b3 [2] ea 9f [2] c4 bd [2] d0 a6 [2] df bc [2] c1 a1 [2] c3 a0 [2] d8 a6 [2] c4 a1 [2] d8 8e }

  condition:
    any of them
}