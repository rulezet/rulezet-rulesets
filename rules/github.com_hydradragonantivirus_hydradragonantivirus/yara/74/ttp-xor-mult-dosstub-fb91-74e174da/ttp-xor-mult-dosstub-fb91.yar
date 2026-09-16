rule TTP_XOR_MULT_DOSStub_fb91 {
  strings:
    $key_fb91 = { af f9 [2] db e1 [2] 9c e3 [2] db f2 [2] 95 fe [2] 99 f4 [2] 8e ff [2] 95 b1 [2] a8 }

  condition:
    any of them
}