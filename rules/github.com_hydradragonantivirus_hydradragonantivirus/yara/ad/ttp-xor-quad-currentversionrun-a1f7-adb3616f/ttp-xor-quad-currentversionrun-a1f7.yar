rule TTP_XOR_QUAD_CurrentVersionRun_a1f7 {
  strings:
    $key_a1f7 = { f2 98 [2] d6 96 [2] fd ba [2] d3 98 [2] c7 83 [2] c8 99 [2] d6 84 [2] d4 85 [2] cf 83 [2] d3 84 [2] cf ab }

  condition:
    any of them
}