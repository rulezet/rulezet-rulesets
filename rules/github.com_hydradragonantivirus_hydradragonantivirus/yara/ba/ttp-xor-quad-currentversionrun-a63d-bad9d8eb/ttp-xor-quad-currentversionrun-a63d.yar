rule TTP_XOR_QUAD_CurrentVersionRun_a63d {
  strings:
    $key_a63d = { f5 52 [2] d1 5c [2] fa 70 [2] d4 52 [2] c0 49 [2] cf 53 [2] d1 4e [2] d3 4f [2] c8 49 [2] d4 4e [2] c8 61 }

  condition:
    any of them
}