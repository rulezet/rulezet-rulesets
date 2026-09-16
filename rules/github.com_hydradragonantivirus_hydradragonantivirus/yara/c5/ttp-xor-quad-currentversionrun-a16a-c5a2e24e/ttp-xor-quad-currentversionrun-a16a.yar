rule TTP_XOR_QUAD_CurrentVersionRun_a16a {
  strings:
    $key_a16a = { f2 05 [2] d6 0b [2] fd 27 [2] d3 05 [2] c7 1e [2] c8 04 [2] d6 19 [2] d4 18 [2] cf 1e [2] d3 19 [2] cf 36 }

  condition:
    any of them
}