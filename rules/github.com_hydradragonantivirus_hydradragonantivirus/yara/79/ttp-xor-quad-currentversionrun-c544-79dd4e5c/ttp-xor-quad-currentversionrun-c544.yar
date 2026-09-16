rule TTP_XOR_QUAD_CurrentVersionRun_c544 {
  strings:
    $key_c544 = { 96 2b [2] b2 25 [2] 99 09 [2] b7 2b [2] a3 30 [2] ac 2a [2] b2 37 [2] b0 36 [2] ab 30 [2] b7 37 [2] ab 18 }

  condition:
    any of them
}