rule TTP_XOR_QUAD_CurrentVersionRun_c302 {
  strings:
    $key_c302 = { 90 6d [2] b4 63 [2] 9f 4f [2] b1 6d [2] a5 76 [2] aa 6c [2] b4 71 [2] b6 70 [2] ad 76 [2] b1 71 [2] ad 5e }

  condition:
    any of them
}