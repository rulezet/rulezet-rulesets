rule TTP_XOR_QUAD_CurrentVersionRun_dd5a {
  strings:
    $key_dd5a = { 8e 35 [2] aa 3b [2] 81 17 [2] af 35 [2] bb 2e [2] b4 34 [2] aa 29 [2] a8 28 [2] b3 2e [2] af 29 [2] b3 06 }

  condition:
    any of them
}