rule TTP_XOR_QUAD_CurrentVersionRun_a63e {
  strings:
    $key_a63e = { f5 51 [2] d1 5f [2] fa 73 [2] d4 51 [2] c0 4a [2] cf 50 [2] d1 4d [2] d3 4c [2] c8 4a [2] d4 4d [2] c8 62 }

  condition:
    any of them
}