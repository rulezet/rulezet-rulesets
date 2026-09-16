rule TTP_XOR_MULT_DOSStub_c3c8 {
  strings:
    $key_c3c8 = { 97 a0 [2] e3 b8 [2] a4 ba [2] e3 ab [2] ad a7 [2] a1 ad [2] b6 a6 [2] ad e8 [2] 90 }

  condition:
    any of them
}