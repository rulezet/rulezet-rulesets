rule TTP_XOR_QUAD_CurrentVersionRun_c42a {
  strings:
    $key_c42a = { 97 45 [2] b3 4b [2] 98 67 [2] b6 45 [2] a2 5e [2] ad 44 [2] b3 59 [2] b1 58 [2] aa 5e [2] b6 59 [2] aa 76 }

  condition:
    any of them
}