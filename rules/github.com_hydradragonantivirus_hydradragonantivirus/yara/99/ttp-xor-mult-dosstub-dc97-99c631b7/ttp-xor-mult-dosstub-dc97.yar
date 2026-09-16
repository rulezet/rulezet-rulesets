rule TTP_XOR_MULT_DOSStub_dc97 {
  strings:
    $key_dc97 = { 88 ff [2] fc e7 [2] bb e5 [2] fc f4 [2] b2 f8 [2] be f2 [2] a9 f9 [2] b2 b7 [2] 8f }

  condition:
    any of them
}