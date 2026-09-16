rule TTP_XOR_QUAD_CurrentVersionRun_c577 {
  strings:
    $key_c577 = { 96 18 [2] b2 16 [2] 99 3a [2] b7 18 [2] a3 03 [2] ac 19 [2] b2 04 [2] b0 05 [2] ab 03 [2] b7 04 [2] ab 2b }

  condition:
    any of them
}