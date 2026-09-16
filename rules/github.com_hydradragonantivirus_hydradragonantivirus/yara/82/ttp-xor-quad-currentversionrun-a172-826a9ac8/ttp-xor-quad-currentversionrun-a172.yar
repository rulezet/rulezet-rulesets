rule TTP_XOR_QUAD_CurrentVersionRun_a172 {
  strings:
    $key_a172 = { f2 1d [2] d6 13 [2] fd 3f [2] d3 1d [2] c7 06 [2] c8 1c [2] d6 01 [2] d4 00 [2] cf 06 [2] d3 01 [2] cf 2e }

  condition:
    any of them
}