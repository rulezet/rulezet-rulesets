rule TTP_XOR_QUAD_CurrentVersionRun_c322 {
  strings:
    $key_c322 = { 90 4d [2] b4 43 [2] 9f 6f [2] b1 4d [2] a5 56 [2] aa 4c [2] b4 51 [2] b6 50 [2] ad 56 [2] b1 51 [2] ad 7e }

  condition:
    any of them
}