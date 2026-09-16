rule TTP_XOR_MULT_DOSStub_c590 {
  strings:
    $key_c590 = { 91 f8 [2] e5 e0 [2] a2 e2 [2] e5 f3 [2] ab ff [2] a7 f5 [2] b0 fe [2] ab b0 [2] 96 }

  condition:
    any of them
}