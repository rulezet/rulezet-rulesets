rule TTP_XOR_MULT_DOSStub_fb97 {
  strings:
    $key_fb97 = { af ff [2] db e7 [2] 9c e5 [2] db f4 [2] 95 f8 [2] 99 f2 [2] 8e f9 [2] 95 b7 [2] a8 }

  condition:
    any of them
}