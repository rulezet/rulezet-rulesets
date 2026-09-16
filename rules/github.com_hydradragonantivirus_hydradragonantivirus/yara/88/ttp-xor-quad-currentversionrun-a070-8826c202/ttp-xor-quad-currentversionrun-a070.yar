rule TTP_XOR_QUAD_CurrentVersionRun_a070 {
  strings:
    $key_a070 = { f3 1f [2] d7 11 [2] fc 3d [2] d2 1f [2] c6 04 [2] c9 1e [2] d7 03 [2] d5 02 [2] ce 04 [2] d2 03 [2] ce 2c }

  condition:
    any of them
}