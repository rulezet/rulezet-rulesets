rule TTP_XOR_QUAD_CurrentVersionRun_a14a {
  strings:
    $key_a14a = { f2 25 [2] d6 2b [2] fd 07 [2] d3 25 [2] c7 3e [2] c8 24 [2] d6 39 [2] d4 38 [2] cf 3e [2] d3 39 [2] cf 16 }

  condition:
    any of them
}