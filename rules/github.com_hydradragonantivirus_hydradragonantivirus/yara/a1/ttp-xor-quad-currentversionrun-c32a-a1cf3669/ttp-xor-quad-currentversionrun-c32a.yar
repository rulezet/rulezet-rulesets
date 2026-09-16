rule TTP_XOR_QUAD_CurrentVersionRun_c32a {
  strings:
    $key_c32a = { 90 45 [2] b4 4b [2] 9f 67 [2] b1 45 [2] a5 5e [2] aa 44 [2] b4 59 [2] b6 58 [2] ad 5e [2] b1 59 [2] ad 76 }

  condition:
    any of them
}