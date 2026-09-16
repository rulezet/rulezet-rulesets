rule TTP_XOR_QUAD_CurrentVersionRun_dd72 {
  strings:
    $key_dd72 = { 8e 1d [2] aa 13 [2] 81 3f [2] af 1d [2] bb 06 [2] b4 1c [2] aa 01 [2] a8 00 [2] b3 06 [2] af 01 [2] b3 2e }

  condition:
    any of them
}