rule TTP_XOR_QUAD_CurrentVersionRun_c31a {
  strings:
    $key_c31a = { 90 75 [2] b4 7b [2] 9f 57 [2] b1 75 [2] a5 6e [2] aa 74 [2] b4 69 [2] b6 68 [2] ad 6e [2] b1 69 [2] ad 46 }

  condition:
    any of them
}