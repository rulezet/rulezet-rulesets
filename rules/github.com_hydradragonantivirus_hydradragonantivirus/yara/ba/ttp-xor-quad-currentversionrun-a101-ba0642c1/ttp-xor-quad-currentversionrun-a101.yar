rule TTP_XOR_QUAD_CurrentVersionRun_a101 {
  strings:
    $key_a101 = { f2 6e [2] d6 60 [2] fd 4c [2] d3 6e [2] c7 75 [2] c8 6f [2] d6 72 [2] d4 73 [2] cf 75 [2] d3 72 [2] cf 5d }

  condition:
    any of them
}