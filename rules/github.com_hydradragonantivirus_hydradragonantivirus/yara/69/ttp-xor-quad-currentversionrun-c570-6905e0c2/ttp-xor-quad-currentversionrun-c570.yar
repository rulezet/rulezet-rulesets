rule TTP_XOR_QUAD_CurrentVersionRun_c570 {
  strings:
    $key_c570 = { 96 1f [2] b2 11 [2] 99 3d [2] b7 1f [2] a3 04 [2] ac 1e [2] b2 03 [2] b0 02 [2] ab 04 [2] b7 03 [2] ab 2c }

  condition:
    any of them
}