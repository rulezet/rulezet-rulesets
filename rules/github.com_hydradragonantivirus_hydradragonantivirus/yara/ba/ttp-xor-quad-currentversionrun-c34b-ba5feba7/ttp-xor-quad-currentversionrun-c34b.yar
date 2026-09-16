rule TTP_XOR_QUAD_CurrentVersionRun_c34b {
  strings:
    $key_c34b = { 90 24 [2] b4 2a [2] 9f 06 [2] b1 24 [2] a5 3f [2] aa 25 [2] b4 38 [2] b6 39 [2] ad 3f [2] b1 38 [2] ad 17 }

  condition:
    any of them
}