rule TTP_XOR_MULT_DOSStub_dcde {
  strings:
    $key_dcde = { 88 b6 [2] fc ae [2] bb ac [2] fc bd [2] b2 b1 [2] be bb [2] a9 b0 [2] b2 fe [2] 8f }

  condition:
    any of them
}