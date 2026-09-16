rule TTP_XOR_MULT_DOSStub_fb95 {
  strings:
    $key_fb95 = { af fd [2] db e5 [2] 9c e7 [2] db f6 [2] 95 fa [2] 99 f0 [2] 8e fb [2] 95 b5 [2] a8 }

  condition:
    any of them
}