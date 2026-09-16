rule TTP_XOR_QUAD_CurrentVersionRun_a6eb {
  strings:
    $key_a6eb = { f5 84 [2] d1 8a [2] fa a6 [2] d4 84 [2] c0 9f [2] cf 85 [2] d1 98 [2] d3 99 [2] c8 9f [2] d4 98 [2] c8 b7 }

  condition:
    any of them
}