rule TTP_XOR_QUAD_CurrentVersionRun_c45b {
  strings:
    $key_c45b = { 97 34 [2] b3 3a [2] 98 16 [2] b6 34 [2] a2 2f [2] ad 35 [2] b3 28 [2] b1 29 [2] aa 2f [2] b6 28 [2] aa 07 }

  condition:
    any of them
}