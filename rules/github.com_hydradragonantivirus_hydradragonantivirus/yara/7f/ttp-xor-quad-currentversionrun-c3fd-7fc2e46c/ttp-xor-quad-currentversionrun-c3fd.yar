rule TTP_XOR_QUAD_CurrentVersionRun_c3fd {
  strings:
    $key_c3fd = { 90 92 [2] b4 9c [2] 9f b0 [2] b1 92 [2] a5 89 [2] aa 93 [2] b4 8e [2] b6 8f [2] ad 89 [2] b1 8e [2] ad a1 }

  condition:
    any of them
}