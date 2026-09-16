rule TTP_XOR_QUAD_CurrentVersionRun_a6f0 {
  strings:
    $key_a6f0 = { f5 9f [2] d1 91 [2] fa bd [2] d4 9f [2] c0 84 [2] cf 9e [2] d1 83 [2] d3 82 [2] c8 84 [2] d4 83 [2] c8 ac }

  condition:
    any of them
}