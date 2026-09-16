rule TTP_XOR_QUAD_CurrentVersionRun_b6f7 {
  strings:
    $key_b6f7 = { e5 98 [2] c1 96 [2] ea ba [2] c4 98 [2] d0 83 [2] df 99 [2] c1 84 [2] c3 85 [2] d8 83 [2] c4 84 [2] d8 ab }

  condition:
    any of them
}