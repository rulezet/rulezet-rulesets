rule TTP_XOR_QUAD_CurrentVersionRun_b1f7 {
  strings:
    $key_b1f7 = { e2 98 [2] c6 96 [2] ed ba [2] c3 98 [2] d7 83 [2] d8 99 [2] c6 84 [2] c4 85 [2] df 83 [2] c3 84 [2] df ab }

  condition:
    any of them
}