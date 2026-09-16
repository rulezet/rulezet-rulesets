rule TTP_XOR_QUAD_CurrentVersionRun_a129 {
  strings:
    $key_a129 = { f2 46 [2] d6 48 [2] fd 64 [2] d3 46 [2] c7 5d [2] c8 47 [2] d6 5a [2] d4 5b [2] cf 5d [2] d3 5a [2] cf 75 }

  condition:
    any of them
}