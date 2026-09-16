rule TTP_XOR_QUAD_CurrentVersionRun_c4fa {
  strings:
    $key_c4fa = { 97 95 [2] b3 9b [2] 98 b7 [2] b6 95 [2] a2 8e [2] ad 94 [2] b3 89 [2] b1 88 [2] aa 8e [2] b6 89 [2] aa a6 }

  condition:
    any of them
}