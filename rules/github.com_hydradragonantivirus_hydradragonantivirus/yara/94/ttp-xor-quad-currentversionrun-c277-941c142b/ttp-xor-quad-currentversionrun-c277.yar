rule TTP_XOR_QUAD_CurrentVersionRun_c277 {
  strings:
    $key_c277 = { 91 18 [2] b5 16 [2] 9e 3a [2] b0 18 [2] a4 03 [2] ab 19 [2] b5 04 [2] b7 05 [2] ac 03 [2] b0 04 [2] ac 2b }

  condition:
    any of them
}