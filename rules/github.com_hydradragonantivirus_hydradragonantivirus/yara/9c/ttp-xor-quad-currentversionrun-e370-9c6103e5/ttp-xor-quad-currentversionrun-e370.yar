rule TTP_XOR_QUAD_CurrentVersionRun_e370 {
  strings:
    $key_e370 = { b0 1f [2] 94 11 [2] bf 3d [2] 91 1f [2] 85 04 [2] 8a 1e [2] 94 03 [2] 96 02 [2] 8d 04 [2] 91 03 [2] 8d 2c }

  condition:
    any of them
}