rule TTP_XOR_QUAD_CurrentVersionRun_b6ed {
  strings:
    $key_b6ed = { e5 82 [2] c1 8c [2] ea a0 [2] c4 82 [2] d0 99 [2] df 83 [2] c1 9e [2] c3 9f [2] d8 99 [2] c4 9e [2] d8 b1 }

  condition:
    any of them
}