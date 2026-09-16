rule TTP_XOR_QUAD_CurrentVersionRun_c3e0 {
  strings:
    $key_c3e0 = { 90 8f [2] b4 81 [2] 9f ad [2] b1 8f [2] a5 94 [2] aa 8e [2] b4 93 [2] b6 92 [2] ad 94 [2] b1 93 [2] ad bc }

  condition:
    any of them
}