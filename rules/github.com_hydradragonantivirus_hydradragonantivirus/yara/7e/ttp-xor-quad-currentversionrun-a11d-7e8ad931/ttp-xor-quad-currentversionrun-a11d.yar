rule TTP_XOR_QUAD_CurrentVersionRun_a11d {
  strings:
    $key_a11d = { f2 72 [2] d6 7c [2] fd 50 [2] d3 72 [2] c7 69 [2] c8 73 [2] d6 6e [2] d4 6f [2] cf 69 [2] d3 6e [2] cf 41 }

  condition:
    any of them
}