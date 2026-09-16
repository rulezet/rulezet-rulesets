rule TTP_XOR_MULT_DOSStub_c59c {
  strings:
    $key_c59c = { 91 f4 [2] e5 ec [2] a2 ee [2] e5 ff [2] ab f3 [2] a7 f9 [2] b0 f2 [2] ab bc [2] 96 }

  condition:
    any of them
}