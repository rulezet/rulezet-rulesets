rule TTP_XOR_QUAD_CurrentVersionRun_a150 {
  strings:
    $key_a150 = { f2 3f [2] d6 31 [2] fd 1d [2] d3 3f [2] c7 24 [2] c8 3e [2] d6 23 [2] d4 22 [2] cf 24 [2] d3 23 [2] cf 0c }

  condition:
    any of them
}