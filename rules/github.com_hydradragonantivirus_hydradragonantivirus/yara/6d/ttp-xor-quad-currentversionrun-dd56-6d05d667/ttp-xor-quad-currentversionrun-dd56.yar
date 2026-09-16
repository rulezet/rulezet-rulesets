rule TTP_XOR_QUAD_CurrentVersionRun_dd56 {
  strings:
    $key_dd56 = { 8e 39 [2] aa 37 [2] 81 1b [2] af 39 [2] bb 22 [2] b4 38 [2] aa 25 [2] a8 24 [2] b3 22 [2] af 25 [2] b3 0a }

  condition:
    any of them
}