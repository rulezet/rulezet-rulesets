rule TTP_XOR_QUAD_CurrentVersionRun_c46a {
  strings:
    $key_c46a = { 97 05 [2] b3 0b [2] 98 27 [2] b6 05 [2] a2 1e [2] ad 04 [2] b3 19 [2] b1 18 [2] aa 1e [2] b6 19 [2] aa 36 }

  condition:
    any of them
}