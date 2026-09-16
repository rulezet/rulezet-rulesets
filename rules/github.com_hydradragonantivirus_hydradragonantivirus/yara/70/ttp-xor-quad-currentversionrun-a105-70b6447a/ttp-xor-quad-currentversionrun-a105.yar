rule TTP_XOR_QUAD_CurrentVersionRun_a105 {
  strings:
    $key_a105 = { f2 6a [2] d6 64 [2] fd 48 [2] d3 6a [2] c7 71 [2] c8 6b [2] d6 76 [2] d4 77 [2] cf 71 [2] d3 76 [2] cf 59 }

  condition:
    any of them
}