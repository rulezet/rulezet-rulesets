rule TTP_XOR_QUAD_CurrentVersionRun_c30a {
  strings:
    $key_c30a = { 90 65 [2] b4 6b [2] 9f 47 [2] b1 65 [2] a5 7e [2] aa 64 [2] b4 79 [2] b6 78 [2] ad 7e [2] b1 79 [2] ad 56 }

  condition:
    any of them
}