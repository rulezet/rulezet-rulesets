rule TTP_XOR_QUAD_CurrentVersionRun_d770 {
  strings:
    $key_d770 = { 84 1f [2] a0 11 [2] 8b 3d [2] a5 1f [2] b1 04 [2] be 1e [2] a0 03 [2] a2 02 [2] b9 04 [2] a5 03 [2] b9 2c }

  condition:
    any of them
}