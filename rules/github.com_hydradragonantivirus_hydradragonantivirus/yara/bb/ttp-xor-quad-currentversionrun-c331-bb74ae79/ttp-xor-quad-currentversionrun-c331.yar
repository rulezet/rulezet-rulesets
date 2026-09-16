rule TTP_XOR_QUAD_CurrentVersionRun_c331 {
  strings:
    $key_c331 = { 90 5e [2] b4 50 [2] 9f 7c [2] b1 5e [2] a5 45 [2] aa 5f [2] b4 42 [2] b6 43 [2] ad 45 [2] b1 42 [2] ad 6d }

  condition:
    any of them
}