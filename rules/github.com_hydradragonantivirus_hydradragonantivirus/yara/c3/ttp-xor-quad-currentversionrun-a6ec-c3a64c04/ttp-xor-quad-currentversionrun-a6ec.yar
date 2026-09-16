rule TTP_XOR_QUAD_CurrentVersionRun_a6ec {
  strings:
    $key_a6ec = { f5 83 [2] d1 8d [2] fa a1 [2] d4 83 [2] c0 98 [2] cf 82 [2] d1 9f [2] d3 9e [2] c8 98 [2] d4 9f [2] c8 b0 }

  condition:
    any of them
}