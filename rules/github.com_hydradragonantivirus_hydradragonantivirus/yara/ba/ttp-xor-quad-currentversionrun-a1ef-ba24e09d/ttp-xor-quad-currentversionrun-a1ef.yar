rule TTP_XOR_QUAD_CurrentVersionRun_a1ef {
  strings:
    $key_a1ef = { f2 80 [2] d6 8e [2] fd a2 [2] d3 80 [2] c7 9b [2] c8 81 [2] d6 9c [2] d4 9d [2] cf 9b [2] d3 9c [2] cf b3 }

  condition:
    any of them
}