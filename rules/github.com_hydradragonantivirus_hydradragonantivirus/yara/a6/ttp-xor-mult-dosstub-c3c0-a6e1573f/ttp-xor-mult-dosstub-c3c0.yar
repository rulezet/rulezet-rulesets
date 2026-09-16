rule TTP_XOR_MULT_DOSStub_c3c0 {
  strings:
    $key_c3c0 = { 97 a8 [2] e3 b0 [2] a4 b2 [2] e3 a3 [2] ad af [2] a1 a5 [2] b6 ae [2] ad e0 [2] 90 }

  condition:
    any of them
}