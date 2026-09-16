rule TTP_XOR_QUAD_CurrentVersionRun_a135 {
  strings:
    $key_a135 = { f2 5a [2] d6 54 [2] fd 78 [2] d3 5a [2] c7 41 [2] c8 5b [2] d6 46 [2] d4 47 [2] cf 41 [2] d3 46 [2] cf 69 }

  condition:
    any of them
}