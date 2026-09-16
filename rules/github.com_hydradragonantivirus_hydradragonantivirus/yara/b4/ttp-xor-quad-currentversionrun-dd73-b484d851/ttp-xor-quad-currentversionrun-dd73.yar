rule TTP_XOR_QUAD_CurrentVersionRun_dd73 {
  strings:
    $key_dd73 = { 8e 1c [2] aa 12 [2] 81 3e [2] af 1c [2] bb 07 [2] b4 1d [2] aa 00 [2] a8 01 [2] b3 07 [2] af 00 [2] b3 2f }

  condition:
    any of them
}