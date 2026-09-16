rule TTP_XOR_QUAD_CurrentVersionRun_c3ef {
  strings:
    $key_c3ef = { 90 80 [2] b4 8e [2] 9f a2 [2] b1 80 [2] a5 9b [2] aa 81 [2] b4 9c [2] b6 9d [2] ad 9b [2] b1 9c [2] ad b3 }

  condition:
    any of them
}