rule TTP_XOR_QUAD_CurrentVersionRun_a17f {
  strings:
    $key_a17f = { f2 10 [2] d6 1e [2] fd 32 [2] d3 10 [2] c7 0b [2] c8 11 [2] d6 0c [2] d4 0d [2] cf 0b [2] d3 0c [2] cf 23 }

  condition:
    any of them
}