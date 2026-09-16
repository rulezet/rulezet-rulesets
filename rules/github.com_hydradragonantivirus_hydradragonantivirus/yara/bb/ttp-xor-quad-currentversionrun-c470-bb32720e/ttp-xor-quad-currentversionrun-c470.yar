rule TTP_XOR_QUAD_CurrentVersionRun_c470 {
  strings:
    $key_c470 = { 97 1f [2] b3 11 [2] 98 3d [2] b6 1f [2] a2 04 [2] ad 1e [2] b3 03 [2] b1 02 [2] aa 04 [2] b6 03 [2] aa 2c }

  condition:
    any of them
}