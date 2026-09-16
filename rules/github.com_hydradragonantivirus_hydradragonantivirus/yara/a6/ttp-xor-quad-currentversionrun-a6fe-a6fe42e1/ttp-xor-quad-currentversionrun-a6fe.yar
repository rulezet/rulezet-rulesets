rule TTP_XOR_QUAD_CurrentVersionRun_a6fe {
  strings:
    $key_a6fe = { f5 91 [2] d1 9f [2] fa b3 [2] d4 91 [2] c0 8a [2] cf 90 [2] d1 8d [2] d3 8c [2] c8 8a [2] d4 8d [2] c8 a2 }

  condition:
    any of them
}