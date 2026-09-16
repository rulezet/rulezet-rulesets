rule TTP_XOR_MULT_DOSStub_c387 {
  strings:
    $key_c387 = { 97 ef [2] e3 f7 [2] a4 f5 [2] e3 e4 [2] ad e8 [2] a1 e2 [2] b6 e9 [2] ad a7 [2] 90 }

  condition:
    any of them
}