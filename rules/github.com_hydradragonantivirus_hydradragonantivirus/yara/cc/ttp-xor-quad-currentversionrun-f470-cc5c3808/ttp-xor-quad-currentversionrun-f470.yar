rule TTP_XOR_QUAD_CurrentVersionRun_f470 {
  strings:
    $key_f470 = { a7 1f [2] 83 11 [2] a8 3d [2] 86 1f [2] 92 04 [2] 9d 1e [2] 83 03 [2] 81 02 [2] 9a 04 [2] 86 03 [2] 9a 2c }

  condition:
    any of them
}