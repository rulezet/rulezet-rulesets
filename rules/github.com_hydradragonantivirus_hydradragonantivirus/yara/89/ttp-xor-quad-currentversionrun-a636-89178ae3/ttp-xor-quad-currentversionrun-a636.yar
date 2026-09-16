rule TTP_XOR_QUAD_CurrentVersionRun_a636 {
  strings:
    $key_a636 = { f5 59 [2] d1 57 [2] fa 7b [2] d4 59 [2] c0 42 [2] cf 58 [2] d1 45 [2] d3 44 [2] c8 42 [2] d4 45 [2] c8 6a }

  condition:
    any of them
}