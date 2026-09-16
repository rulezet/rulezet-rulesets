rule TTP_XOR_QUAD_CurrentVersionRun_dd66 {
  strings:
    $key_dd66 = { 8e 09 [2] aa 07 [2] 81 2b [2] af 09 [2] bb 12 [2] b4 08 [2] aa 15 [2] a8 14 [2] b3 12 [2] af 15 [2] b3 3a }

  condition:
    any of them
}