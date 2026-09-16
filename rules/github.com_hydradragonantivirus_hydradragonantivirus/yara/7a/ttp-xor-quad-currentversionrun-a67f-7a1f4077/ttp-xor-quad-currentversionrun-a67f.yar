rule TTP_XOR_QUAD_CurrentVersionRun_a67f {
  strings:
    $key_a67f = { f5 10 [2] d1 1e [2] fa 32 [2] d4 10 [2] c0 0b [2] cf 11 [2] d1 0c [2] d3 0d [2] c8 0b [2] d4 0c [2] c8 23 }

  condition:
    any of them
}