rule TTP_XOR_MULT_DOSStub_fb90 {
  strings:
    $key_fb90 = { af f8 [2] db e0 [2] 9c e2 [2] db f3 [2] 95 ff [2] 99 f5 [2] 8e fe [2] 95 b0 [2] a8 }

  condition:
    any of them
}