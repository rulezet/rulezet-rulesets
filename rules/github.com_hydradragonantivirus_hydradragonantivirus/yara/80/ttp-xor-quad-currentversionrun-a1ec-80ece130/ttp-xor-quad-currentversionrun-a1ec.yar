rule TTP_XOR_QUAD_CurrentVersionRun_a1ec {
  strings:
    $key_a1ec = { f2 83 [2] d6 8d [2] fd a1 [2] d3 83 [2] c7 98 [2] c8 82 [2] d6 9f [2] d4 9e [2] cf 98 [2] d3 9f [2] cf b0 }

  condition:
    any of them
}