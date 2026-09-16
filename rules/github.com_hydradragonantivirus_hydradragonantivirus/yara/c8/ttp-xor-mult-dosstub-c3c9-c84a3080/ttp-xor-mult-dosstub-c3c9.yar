rule TTP_XOR_MULT_DOSStub_c3c9 {
  strings:
    $key_c3c9 = { 97 a1 [2] e3 b9 [2] a4 bb [2] e3 aa [2] ad a6 [2] a1 ac [2] b6 a7 [2] ad e9 [2] 90 }

  condition:
    any of them
}