rule TTP_XOR_QUAD_CurrentVersionRun_a163 {
  strings:
    $key_a163 = { f2 0c [2] d6 02 [2] fd 2e [2] d3 0c [2] c7 17 [2] c8 0d [2] d6 10 [2] d4 11 [2] cf 17 [2] d3 10 [2] cf 3f }

  condition:
    any of them
}