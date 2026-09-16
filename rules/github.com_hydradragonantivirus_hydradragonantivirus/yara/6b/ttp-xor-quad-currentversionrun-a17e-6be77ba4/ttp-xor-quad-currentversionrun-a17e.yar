rule TTP_XOR_QUAD_CurrentVersionRun_a17e {
  strings:
    $key_a17e = { f2 11 [2] d6 1f [2] fd 33 [2] d3 11 [2] c7 0a [2] c8 10 [2] d6 0d [2] d4 0c [2] cf 0a [2] d3 0d [2] cf 22 }

  condition:
    any of them
}