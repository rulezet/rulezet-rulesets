rule TTP_XOR_QUAD_CurrentVersionRun_a15d {
  strings:
    $key_a15d = { f2 32 [2] d6 3c [2] fd 10 [2] d3 32 [2] c7 29 [2] c8 33 [2] d6 2e [2] d4 2f [2] cf 29 [2] d3 2e [2] cf 01 }

  condition:
    any of them
}