rule TTP_XOR_MULT_DOSStub_c3c3 {
  strings:
    $key_c3c3 = { 97 ab [2] e3 b3 [2] a4 b1 [2] e3 a0 [2] ad ac [2] a1 a6 [2] b6 ad [2] ad e3 [2] 90 }

  condition:
    any of them
}