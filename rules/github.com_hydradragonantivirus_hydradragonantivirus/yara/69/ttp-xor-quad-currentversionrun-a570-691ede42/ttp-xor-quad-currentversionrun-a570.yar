rule TTP_XOR_QUAD_CurrentVersionRun_a570 {
  strings:
    $key_a570 = { f6 1f [2] d2 11 [2] f9 3d [2] d7 1f [2] c3 04 [2] cc 1e [2] d2 03 [2] d0 02 [2] cb 04 [2] d7 03 [2] cb 2c }

  condition:
    any of them
}