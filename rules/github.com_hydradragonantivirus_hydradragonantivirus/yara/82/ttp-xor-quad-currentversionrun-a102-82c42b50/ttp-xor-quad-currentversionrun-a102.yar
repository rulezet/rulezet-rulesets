rule TTP_XOR_QUAD_CurrentVersionRun_a102 {
  strings:
    $key_a102 = { f2 6d [2] d6 63 [2] fd 4f [2] d3 6d [2] c7 76 [2] c8 6c [2] d6 71 [2] d4 70 [2] cf 76 [2] d3 71 [2] cf 5e }

  condition:
    any of them
}