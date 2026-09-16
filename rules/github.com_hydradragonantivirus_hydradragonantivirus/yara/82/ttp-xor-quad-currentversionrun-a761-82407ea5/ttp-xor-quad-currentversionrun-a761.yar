rule TTP_XOR_QUAD_CurrentVersionRun_a761 {
  strings:
    $key_a761 = { f4 0e [2] d0 00 [2] fb 2c [2] d5 0e [2] c1 15 [2] ce 0f [2] d0 12 [2] d2 13 [2] c9 15 [2] d5 12 [2] c9 3d }

  condition:
    any of them
}