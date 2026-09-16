rule TTP_XOR_QUAD_CurrentVersionRun_a66e {
  strings:
    $key_a66e = { f5 01 [2] d1 0f [2] fa 23 [2] d4 01 [2] c0 1a [2] cf 00 [2] d1 1d [2] d3 1c [2] c8 1a [2] d4 1d [2] c8 32 }

  condition:
    any of them
}