rule TTP_XOR_QUAD_CurrentVersionRun_a600 {
  strings:
    $key_a600 = { f5 6f [2] d1 61 [2] fa 4d [2] d4 6f [2] c0 74 [2] cf 6e [2] d1 73 [2] d3 72 [2] c8 74 [2] d4 73 [2] c8 5c }

  condition:
    any of them
}