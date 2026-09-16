rule TTP_XOR_QUAD_CurrentVersionRun_a12c {
  strings:
    $key_a12c = { f2 43 [2] d6 4d [2] fd 61 [2] d3 43 [2] c7 58 [2] c8 42 [2] d6 5f [2] d4 5e [2] cf 58 [2] d3 5f [2] cf 70 }

  condition:
    any of them
}