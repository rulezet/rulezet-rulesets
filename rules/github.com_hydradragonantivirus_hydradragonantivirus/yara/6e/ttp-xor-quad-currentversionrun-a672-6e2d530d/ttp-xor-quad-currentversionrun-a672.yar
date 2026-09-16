rule TTP_XOR_QUAD_CurrentVersionRun_a672 {
  strings:
    $key_a672 = { f5 1d [2] d1 13 [2] fa 3f [2] d4 1d [2] c0 06 [2] cf 1c [2] d1 01 [2] d3 00 [2] c8 06 [2] d4 01 [2] c8 2e }

  condition:
    any of them
}