rule TTP_XOR_QUAD_CurrentVersionRun_dd27 {
  strings:
    $key_dd27 = { 8e 48 [2] aa 46 [2] 81 6a [2] af 48 [2] bb 53 [2] b4 49 [2] aa 54 [2] a8 55 [2] b3 53 [2] af 54 [2] b3 7b }

  condition:
    any of them
}