rule TTP_XOR_QUAD_CurrentVersionRun_f070 {
  strings:
    $key_f070 = { a3 1f [2] 87 11 [2] ac 3d [2] 82 1f [2] 96 04 [2] 99 1e [2] 87 03 [2] 85 02 [2] 9e 04 [2] 82 03 [2] 9e 2c }

  condition:
    any of them
}