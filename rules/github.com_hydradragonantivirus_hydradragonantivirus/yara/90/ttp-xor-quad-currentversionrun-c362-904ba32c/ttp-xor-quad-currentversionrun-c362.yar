rule TTP_XOR_QUAD_CurrentVersionRun_c362 {
  strings:
    $key_c362 = { 90 0d [2] b4 03 [2] 9f 2f [2] b1 0d [2] a5 16 [2] aa 0c [2] b4 11 [2] b6 10 [2] ad 16 [2] b1 11 [2] ad 3e }

  condition:
    any of them
}