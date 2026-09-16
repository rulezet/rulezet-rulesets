rule TTP_XOR_QUAD_CurrentVersionRun_a165 {
  strings:
    $key_a165 = { f2 0a [2] d6 04 [2] fd 28 [2] d3 0a [2] c7 11 [2] c8 0b [2] d6 16 [2] d4 17 [2] cf 11 [2] d3 16 [2] cf 39 }

  condition:
    any of them
}