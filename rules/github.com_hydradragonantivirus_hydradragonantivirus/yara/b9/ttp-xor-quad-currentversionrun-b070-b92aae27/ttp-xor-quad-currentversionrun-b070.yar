rule TTP_XOR_QUAD_CurrentVersionRun_b070 {
  strings:
    $key_b070 = { e3 1f [2] c7 11 [2] ec 3d [2] c2 1f [2] d6 04 [2] d9 1e [2] c7 03 [2] c5 02 [2] de 04 [2] c2 03 [2] de 2c }

  condition:
    any of them
}