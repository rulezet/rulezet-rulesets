rule TTP_XOR_QUAD_CurrentVersionRun_a6e1 {
  strings:
    $key_a6e1 = { f5 8e [2] d1 80 [2] fa ac [2] d4 8e [2] c0 95 [2] cf 8f [2] d1 92 [2] d3 93 [2] c8 95 [2] d4 92 [2] c8 bd }

  condition:
    any of them
}