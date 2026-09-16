rule TTP_XOR_QUAD_CurrentVersionRun_de58 {
  strings:
    $key_de58 = { 8d 37 [2] a9 39 [2] 82 15 [2] ac 37 [2] b8 2c [2] b7 36 [2] a9 2b [2] ab 2a [2] b0 2c [2] ac 2b [2] b0 04 }

  condition:
    any of them
}