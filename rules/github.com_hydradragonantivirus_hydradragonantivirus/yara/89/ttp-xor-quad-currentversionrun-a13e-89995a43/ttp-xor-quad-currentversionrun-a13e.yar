rule TTP_XOR_QUAD_CurrentVersionRun_a13e {
  strings:
    $key_a13e = { f2 51 [2] d6 5f [2] fd 73 [2] d3 51 [2] c7 4a [2] c8 50 [2] d6 4d [2] d4 4c [2] cf 4a [2] d3 4d [2] cf 62 }

  condition:
    any of them
}