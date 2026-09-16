rule TTP_XOR_QUAD_CurrentVersionRun_a664 {
  strings:
    $key_a664 = { f5 0b [2] d1 05 [2] fa 29 [2] d4 0b [2] c0 10 [2] cf 0a [2] d1 17 [2] d3 16 [2] c8 10 [2] d4 17 [2] c8 38 }

  condition:
    any of them
}