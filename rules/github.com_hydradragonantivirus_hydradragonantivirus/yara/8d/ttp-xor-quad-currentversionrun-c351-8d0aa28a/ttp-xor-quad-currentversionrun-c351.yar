rule TTP_XOR_QUAD_CurrentVersionRun_c351 {
  strings:
    $key_c351 = { 90 3e [2] b4 30 [2] 9f 1c [2] b1 3e [2] a5 25 [2] aa 3f [2] b4 22 [2] b6 23 [2] ad 25 [2] b1 22 [2] ad 0d }

  condition:
    any of them
}