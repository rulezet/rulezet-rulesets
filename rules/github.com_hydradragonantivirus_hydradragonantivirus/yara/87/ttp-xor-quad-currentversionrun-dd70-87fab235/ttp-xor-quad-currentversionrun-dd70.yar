rule TTP_XOR_QUAD_CurrentVersionRun_dd70 {
  strings:
    $key_dd70 = { 8e 1f [2] aa 11 [2] 81 3d [2] af 1f [2] bb 04 [2] b4 1e [2] aa 03 [2] a8 02 [2] b3 04 [2] af 03 [2] b3 2c }

  condition:
    any of them
}