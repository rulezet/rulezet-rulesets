rule TTP_XOR_QUAD_CurrentVersionRun_c3eb {
  strings:
    $key_c3eb = { 90 84 [2] b4 8a [2] 9f a6 [2] b1 84 [2] a5 9f [2] aa 85 [2] b4 98 [2] b6 99 [2] ad 9f [2] b1 98 [2] ad b7 }

  condition:
    any of them
}