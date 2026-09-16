rule TTP_XOR_QUAD_CurrentVersionRun_bb70 {
  strings:
    $key_bb70 = { e8 1f [2] cc 11 [2] e7 3d [2] c9 1f [2] dd 04 [2] d2 1e [2] cc 03 [2] ce 02 [2] d5 04 [2] c9 03 [2] d5 2c }

  condition:
    any of them
}