rule TTP_XOR_QUAD_CurrentVersionRun_a470 {
  strings:
    $key_a470 = { f7 1f [2] d3 11 [2] f8 3d [2] d6 1f [2] c2 04 [2] cd 1e [2] d3 03 [2] d1 02 [2] ca 04 [2] d6 03 [2] ca 2c }

  condition:
    any of them
}