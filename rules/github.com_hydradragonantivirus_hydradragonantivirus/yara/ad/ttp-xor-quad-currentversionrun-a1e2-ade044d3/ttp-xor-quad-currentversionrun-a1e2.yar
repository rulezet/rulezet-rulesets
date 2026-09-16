rule TTP_XOR_QUAD_CurrentVersionRun_a1e2 {
  strings:
    $key_a1e2 = { f2 8d [2] d6 83 [2] fd af [2] d3 8d [2] c7 96 [2] c8 8c [2] d6 91 [2] d4 90 [2] cf 96 [2] d3 91 [2] cf be }

  condition:
    any of them
}