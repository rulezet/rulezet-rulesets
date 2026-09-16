rule TTP_XOR_MULT_DOSStub_c78d {
  strings:
    $key_c78d = { 93 e5 [2] e7 fd [2] a0 ff [2] e7 ee [2] a9 e2 [2] a5 e8 [2] b2 e3 [2] a9 ad [2] 94 }

  condition:
    any of them
}