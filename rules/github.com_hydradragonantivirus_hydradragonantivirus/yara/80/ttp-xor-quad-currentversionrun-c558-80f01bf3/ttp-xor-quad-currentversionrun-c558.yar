rule TTP_XOR_QUAD_CurrentVersionRun_c558 {
  strings:
    $key_c558 = { 96 37 [2] b2 39 [2] 99 15 [2] b7 37 [2] a3 2c [2] ac 36 [2] b2 2b [2] b0 2a [2] ab 2c [2] b7 2b [2] ab 04 }

  condition:
    any of them
}