rule TTP_XOR_QUAD_CurrentVersionRun_d761 {
  strings:
    $key_d761 = { 84 0e [2] a0 00 [2] 8b 2c [2] a5 0e [2] b1 15 [2] be 0f [2] a0 12 [2] a2 13 [2] b9 15 [2] a5 12 [2] b9 3d }

  condition:
    any of them
}