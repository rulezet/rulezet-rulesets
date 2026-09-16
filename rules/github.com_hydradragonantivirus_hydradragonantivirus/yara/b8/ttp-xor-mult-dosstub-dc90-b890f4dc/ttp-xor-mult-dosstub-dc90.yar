rule TTP_XOR_MULT_DOSStub_dc90 {
  strings:
    $key_dc90 = { 88 f8 [2] fc e0 [2] bb e2 [2] fc f3 [2] b2 ff [2] be f5 [2] a9 fe [2] b2 b0 [2] 8f }

  condition:
    any of them
}