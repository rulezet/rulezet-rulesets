rule TTP_XOR_QUAD_CurrentVersionRun_a6fc {
  strings:
    $key_a6fc = { f5 93 [2] d1 9d [2] fa b1 [2] d4 93 [2] c0 88 [2] cf 92 [2] d1 8f [2] d3 8e [2] c8 88 [2] d4 8f [2] c8 a0 }

  condition:
    any of them
}