rule TTP_XOR_QUAD_CurrentVersionRun_d070 {
  strings:
    $key_d070 = { 83 1f [2] a7 11 [2] 8c 3d [2] a2 1f [2] b6 04 [2] b9 1e [2] a7 03 [2] a5 02 [2] be 04 [2] a2 03 [2] be 2c }

  condition:
    any of them
}