rule TTP_XOR_QUAD_CurrentVersionRun_b6f0 {
  strings:
    $key_b6f0 = { e5 9f [2] c1 91 [2] ea bd [2] c4 9f [2] d0 84 [2] df 9e [2] c1 83 [2] c3 82 [2] d8 84 [2] c4 83 [2] d8 ac }

  condition:
    any of them
}