rule TTP_XOR_QUAD_CurrentVersionRun_a111 {
  strings:
    $key_a111 = { f2 7e [2] d6 70 [2] fd 5c [2] d3 7e [2] c7 65 [2] c8 7f [2] d6 62 [2] d4 63 [2] cf 65 [2] d3 62 [2] cf 4d }

  condition:
    any of them
}