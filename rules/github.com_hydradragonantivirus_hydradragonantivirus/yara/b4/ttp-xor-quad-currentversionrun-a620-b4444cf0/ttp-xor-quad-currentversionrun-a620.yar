rule TTP_XOR_QUAD_CurrentVersionRun_a620 {
  strings:
    $key_a620 = { f5 4f [2] d1 41 [2] fa 6d [2] d4 4f [2] c0 54 [2] cf 4e [2] d1 53 [2] d3 52 [2] c8 54 [2] d4 53 [2] c8 7c }

  condition:
    any of them
}