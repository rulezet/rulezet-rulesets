rule TTP_XOR_QUAD_CurrentVersionRun_f570 {
  strings:
    $key_f570 = { a6 1f [2] 82 11 [2] a9 3d [2] 87 1f [2] 93 04 [2] 9c 1e [2] 82 03 [2] 80 02 [2] 9b 04 [2] 87 03 [2] 9b 2c }

  condition:
    any of them
}