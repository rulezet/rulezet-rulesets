rule TTP_XOR_QUAD_CurrentVersionRun_a115 {
  strings:
    $key_a115 = { f2 7a [2] d6 74 [2] fd 58 [2] d3 7a [2] c7 61 [2] c8 7b [2] d6 66 [2] d4 67 [2] cf 61 [2] d3 66 [2] cf 49 }

  condition:
    any of them
}