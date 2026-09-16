rule TTP_XOR_QUAD_CurrentVersionRun_c34a {
  strings:
    $key_c34a = { 90 25 [2] b4 2b [2] 9f 07 [2] b1 25 [2] a5 3e [2] aa 24 [2] b4 39 [2] b6 38 [2] ad 3e [2] b1 39 [2] ad 16 }

  condition:
    any of them
}