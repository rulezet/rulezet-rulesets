rule TTP_XOR_QUAD_CurrentVersionRun_dd76 {
  strings:
    $key_dd76 = { 8e 19 [2] aa 17 [2] 81 3b [2] af 19 [2] bb 02 [2] b4 18 [2] aa 05 [2] a8 04 [2] b3 02 [2] af 05 [2] b3 2a }

  condition:
    any of them
}