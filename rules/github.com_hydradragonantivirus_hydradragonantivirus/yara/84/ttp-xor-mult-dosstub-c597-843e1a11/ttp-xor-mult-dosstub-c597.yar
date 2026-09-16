rule TTP_XOR_MULT_DOSStub_c597 {
  strings:
    $key_c597 = { 91 ff [2] e5 e7 [2] a2 e5 [2] e5 f4 [2] ab f8 [2] a7 f2 [2] b0 f9 [2] ab b7 [2] 96 }

  condition:
    any of them
}