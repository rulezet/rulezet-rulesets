rule TTP_XOR_MULT_DOSStub_c3c1 {
  strings:
    $key_c3c1 = { 97 a9 [2] e3 b1 [2] a4 b3 [2] e3 a2 [2] ad ae [2] a1 a4 [2] b6 af [2] ad e1 [2] 90 }

  condition:
    any of them
}