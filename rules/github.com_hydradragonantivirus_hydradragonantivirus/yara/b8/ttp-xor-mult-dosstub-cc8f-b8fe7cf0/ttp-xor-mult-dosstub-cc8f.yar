rule TTP_XOR_MULT_DOSStub_cc8f {
  strings:
    $key_cc8f = { 98 e7 [2] ec ff [2] ab fd [2] ec ec [2] a2 e0 [2] ae ea [2] b9 e1 [2] a2 af [2] 9f }

  condition:
    any of them
}