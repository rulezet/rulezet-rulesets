rule TTP_XOR_QUAD_CurrentVersionRun_a145 {
  strings:
    $key_a145 = { f2 2a [2] d6 24 [2] fd 08 [2] d3 2a [2] c7 31 [2] c8 2b [2] d6 36 [2] d4 37 [2] cf 31 [2] d3 36 [2] cf 19 }

  condition:
    any of them
}