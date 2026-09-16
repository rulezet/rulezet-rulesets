rule TTP_XOR_QUAD_CurrentVersionRun_a128 {
  strings:
    $key_a128 = { f2 47 [2] d6 49 [2] fd 65 [2] d3 47 [2] c7 5c [2] c8 46 [2] d6 5b [2] d4 5a [2] cf 5c [2] d3 5b [2] cf 74 }

  condition:
    any of them
}