rule TTP_XOR_QUAD_CurrentVersionRun_c4fd {
  strings:
    $key_c4fd = { 97 92 [2] b3 9c [2] 98 b0 [2] b6 92 [2] a2 89 [2] ad 93 [2] b3 8e [2] b1 8f [2] aa 89 [2] b6 8e [2] aa a1 }

  condition:
    any of them
}