rule TTP_XOR_MULT_DOSStub_dc83 {
  strings:
    $key_dc83 = { 88 eb [2] fc f3 [2] bb f1 [2] fc e0 [2] b2 ec [2] be e6 [2] a9 ed [2] b2 a3 [2] 8f }

  condition:
    any of them
}