rule TTP_XOR_MULT_DOSStub_dcd9 {
  strings:
    $key_dcd9 = { 88 b1 [2] fc a9 [2] bb ab [2] fc ba [2] b2 b6 [2] be bc [2] a9 b7 [2] b2 f9 [2] 8f }

  condition:
    any of them
}