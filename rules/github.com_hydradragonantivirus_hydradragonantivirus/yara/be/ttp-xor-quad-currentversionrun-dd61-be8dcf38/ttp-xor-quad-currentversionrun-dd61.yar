rule TTP_XOR_QUAD_CurrentVersionRun_dd61 {
  strings:
    $key_dd61 = { 8e 0e [2] aa 00 [2] 81 2c [2] af 0e [2] bb 15 [2] b4 0f [2] aa 12 [2] a8 13 [2] b3 15 [2] af 12 [2] b3 3d }

  condition:
    any of them
}