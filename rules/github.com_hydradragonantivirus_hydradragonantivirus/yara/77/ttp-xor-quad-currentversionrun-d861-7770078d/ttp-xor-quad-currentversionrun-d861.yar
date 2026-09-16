rule TTP_XOR_QUAD_CurrentVersionRun_d861 {
  strings:
    $key_d861 = { 8b 0e [2] af 00 [2] 84 2c [2] aa 0e [2] be 15 [2] b1 0f [2] af 12 [2] ad 13 [2] b6 15 [2] aa 12 [2] b6 3d }

  condition:
    any of them
}