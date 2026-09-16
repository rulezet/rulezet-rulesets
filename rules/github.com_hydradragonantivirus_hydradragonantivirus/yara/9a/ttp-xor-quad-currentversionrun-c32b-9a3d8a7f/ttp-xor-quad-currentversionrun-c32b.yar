rule TTP_XOR_QUAD_CurrentVersionRun_c32b {
  strings:
    $key_c32b = { 90 44 [2] b4 4a [2] 9f 66 [2] b1 44 [2] a5 5f [2] aa 45 [2] b4 58 [2] b6 59 [2] ad 5f [2] b1 58 [2] ad 77 }

  condition:
    any of them
}