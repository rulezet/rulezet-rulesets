rule TTP_XOR_QUAD_CurrentVersionRun_c427 {
  strings:
    $key_c427 = { 97 48 [2] b3 46 [2] 98 6a [2] b6 48 [2] a2 53 [2] ad 49 [2] b3 54 [2] b1 55 [2] aa 53 [2] b6 54 [2] aa 7b }

  condition:
    any of them
}