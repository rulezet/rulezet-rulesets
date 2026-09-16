rule TTP_XOR_MULT_DOSStub_c591 {
  strings:
    $key_c591 = { 91 f9 [2] e5 e1 [2] a2 e3 [2] e5 f2 [2] ab fe [2] a7 f4 [2] b0 ff [2] ab b1 [2] 96 }

  condition:
    any of them
}