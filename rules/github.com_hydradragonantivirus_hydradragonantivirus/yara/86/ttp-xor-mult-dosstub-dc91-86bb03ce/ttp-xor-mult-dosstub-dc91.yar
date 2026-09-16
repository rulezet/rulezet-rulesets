rule TTP_XOR_MULT_DOSStub_dc91 {
  strings:
    $key_dc91 = { 88 f9 [2] fc e1 [2] bb e3 [2] fc f2 [2] b2 fe [2] be f4 [2] a9 ff [2] b2 b1 [2] 8f }

  condition:
    any of them
}