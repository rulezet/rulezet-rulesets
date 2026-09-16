rule TTP_XOR_QUAD_CurrentVersionRun_a12e {
  strings:
    $key_a12e = { f2 41 [2] d6 4f [2] fd 63 [2] d3 41 [2] c7 5a [2] c8 40 [2] d6 5d [2] d4 5c [2] cf 5a [2] d3 5d [2] cf 72 }

  condition:
    any of them
}