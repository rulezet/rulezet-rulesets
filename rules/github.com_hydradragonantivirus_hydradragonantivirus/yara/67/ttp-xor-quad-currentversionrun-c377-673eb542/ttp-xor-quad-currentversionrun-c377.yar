rule TTP_XOR_QUAD_CurrentVersionRun_c377 {
  strings:
    $key_c377 = { 90 18 [2] b4 16 [2] 9f 3a [2] b1 18 [2] a5 03 [2] aa 19 [2] b4 04 [2] b6 05 [2] ad 03 [2] b1 04 [2] ad 2b }

  condition:
    any of them
}