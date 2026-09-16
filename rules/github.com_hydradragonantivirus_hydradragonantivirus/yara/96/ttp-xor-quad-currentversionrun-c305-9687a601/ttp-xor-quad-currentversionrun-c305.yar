rule TTP_XOR_QUAD_CurrentVersionRun_c305 {
  strings:
    $key_c305 = { 90 6a [2] b4 64 [2] 9f 48 [2] b1 6a [2] a5 71 [2] aa 6b [2] b4 76 [2] b6 77 [2] ad 71 [2] b1 76 [2] ad 59 }

  condition:
    any of them
}