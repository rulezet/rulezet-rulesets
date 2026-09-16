rule TTP_XOR_QUAD_CurrentVersionRun_a67e {
  strings:
    $key_a67e = { f5 11 [2] d1 1f [2] fa 33 [2] d4 11 [2] c0 0a [2] cf 10 [2] d1 0d [2] d3 0c [2] c8 0a [2] d4 0d [2] c8 22 }

  condition:
    any of them
}