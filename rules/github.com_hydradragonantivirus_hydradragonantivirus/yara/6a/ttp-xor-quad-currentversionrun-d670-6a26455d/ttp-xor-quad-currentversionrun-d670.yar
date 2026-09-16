rule TTP_XOR_QUAD_CurrentVersionRun_d670 {
  strings:
    $key_d670 = { 85 1f [2] a1 11 [2] 8a 3d [2] a4 1f [2] b0 04 [2] bf 1e [2] a1 03 [2] a3 02 [2] b8 04 [2] a4 03 [2] b8 2c }

  condition:
    any of them
}