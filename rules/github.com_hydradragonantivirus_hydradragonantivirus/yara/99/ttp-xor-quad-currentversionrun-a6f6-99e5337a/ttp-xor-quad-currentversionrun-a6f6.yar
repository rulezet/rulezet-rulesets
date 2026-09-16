rule TTP_XOR_QUAD_CurrentVersionRun_a6f6 {
  strings:
    $key_a6f6 = { f5 99 [2] d1 97 [2] fa bb [2] d4 99 [2] c0 82 [2] cf 98 [2] d1 85 [2] d3 84 [2] c8 82 [2] d4 85 [2] c8 aa }

  condition:
    any of them
}