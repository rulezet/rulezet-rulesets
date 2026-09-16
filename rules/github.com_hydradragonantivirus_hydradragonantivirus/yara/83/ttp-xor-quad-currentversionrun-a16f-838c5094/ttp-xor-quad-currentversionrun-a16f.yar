rule TTP_XOR_QUAD_CurrentVersionRun_a16f {
  strings:
    $key_a16f = { f2 00 [2] d6 0e [2] fd 22 [2] d3 00 [2] c7 1b [2] c8 01 [2] d6 1c [2] d4 1d [2] cf 1b [2] d3 1c [2] cf 33 }

  condition:
    any of them
}