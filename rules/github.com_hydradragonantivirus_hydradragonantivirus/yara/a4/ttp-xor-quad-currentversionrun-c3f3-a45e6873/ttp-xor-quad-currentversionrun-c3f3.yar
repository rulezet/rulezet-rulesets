rule TTP_XOR_QUAD_CurrentVersionRun_c3f3 {
  strings:
    $key_c3f3 = { 90 9c [2] b4 92 [2] 9f be [2] b1 9c [2] a5 87 [2] aa 9d [2] b4 80 [2] b6 81 [2] ad 87 [2] b1 80 [2] ad af }

  condition:
    any of them
}