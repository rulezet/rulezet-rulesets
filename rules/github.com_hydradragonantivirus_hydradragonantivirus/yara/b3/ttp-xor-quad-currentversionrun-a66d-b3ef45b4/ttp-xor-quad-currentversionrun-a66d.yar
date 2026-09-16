rule TTP_XOR_QUAD_CurrentVersionRun_a66d {
  strings:
    $key_a66d = { f5 02 [2] d1 0c [2] fa 20 [2] d4 02 [2] c0 19 [2] cf 03 [2] d1 1e [2] d3 1f [2] c8 19 [2] d4 1e [2] c8 31 }

  condition:
    any of them
}