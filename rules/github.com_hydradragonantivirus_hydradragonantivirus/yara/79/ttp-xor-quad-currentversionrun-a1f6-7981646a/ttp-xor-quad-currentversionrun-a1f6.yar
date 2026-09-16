rule TTP_XOR_QUAD_CurrentVersionRun_a1f6 {
  strings:
    $key_a1f6 = { f2 99 [2] d6 97 [2] fd bb [2] d3 99 [2] c7 82 [2] c8 98 [2] d6 85 [2] d4 84 [2] cf 82 [2] d3 85 [2] cf aa }

  condition:
    any of them
}