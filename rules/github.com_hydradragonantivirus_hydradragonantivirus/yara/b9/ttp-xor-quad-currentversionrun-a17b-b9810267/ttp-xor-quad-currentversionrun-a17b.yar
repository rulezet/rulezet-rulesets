rule TTP_XOR_QUAD_CurrentVersionRun_a17b {
  strings:
    $key_a17b = { f2 14 [2] d6 1a [2] fd 36 [2] d3 14 [2] c7 0f [2] c8 15 [2] d6 08 [2] d4 09 [2] cf 0f [2] d3 08 [2] cf 27 }

  condition:
    any of them
}