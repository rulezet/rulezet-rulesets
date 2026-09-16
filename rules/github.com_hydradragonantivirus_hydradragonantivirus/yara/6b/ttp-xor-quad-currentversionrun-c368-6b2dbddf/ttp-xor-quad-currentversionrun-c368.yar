rule TTP_XOR_QUAD_CurrentVersionRun_c368 {
  strings:
    $key_c368 = { 90 07 [2] b4 09 [2] 9f 25 [2] b1 07 [2] a5 1c [2] aa 06 [2] b4 1b [2] b6 1a [2] ad 1c [2] b1 1b [2] ad 34 }

  condition:
    any of them
}