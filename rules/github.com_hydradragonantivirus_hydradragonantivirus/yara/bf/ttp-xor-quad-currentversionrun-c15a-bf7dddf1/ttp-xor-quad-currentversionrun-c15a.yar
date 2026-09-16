rule TTP_XOR_QUAD_CurrentVersionRun_c15a {
  strings:
    $key_c15a = { 92 35 [2] b6 3b [2] 9d 17 [2] b3 35 [2] a7 2e [2] a8 34 [2] b6 29 [2] b4 28 [2] af 2e [2] b3 29 [2] af 06 }

  condition:
    any of them
}