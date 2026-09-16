rule TTP_XOR_QUAD_CurrentVersionRun_a62a {
  strings:
    $key_a62a = { f5 45 [2] d1 4b [2] fa 67 [2] d4 45 [2] c0 5e [2] cf 44 [2] d1 59 [2] d3 58 [2] c8 5e [2] d4 59 [2] c8 76 }

  condition:
    any of them
}