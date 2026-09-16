rule TTP_XOR_MULT_DOSStub_c3c2 {
  strings:
    $key_c3c2 = { 97 aa [2] e3 b2 [2] a4 b0 [2] e3 a1 [2] ad ad [2] a1 a7 [2] b6 ac [2] ad e2 [2] 90 }

  condition:
    any of them
}