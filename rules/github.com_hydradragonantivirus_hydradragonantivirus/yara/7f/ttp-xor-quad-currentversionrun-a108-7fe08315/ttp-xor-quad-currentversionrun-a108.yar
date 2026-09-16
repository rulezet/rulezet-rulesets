rule TTP_XOR_QUAD_CurrentVersionRun_a108 {
  strings:
    $key_a108 = { f2 67 [2] d6 69 [2] fd 45 [2] d3 67 [2] c7 7c [2] c8 66 [2] d6 7b [2] d4 7a [2] cf 7c [2] d3 7b [2] cf 54 }

  condition:
    any of them
}