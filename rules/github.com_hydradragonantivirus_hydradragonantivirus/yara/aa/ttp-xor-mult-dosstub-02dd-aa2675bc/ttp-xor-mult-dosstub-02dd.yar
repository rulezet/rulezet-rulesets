rule TTP_XOR_MULT_DOSStub_02dd {
  strings:
    $key_02dd = { 56 b5 [2] 22 ad [2] 65 af [2] 22 be [2] 6c b2 [2] 60 b8 [2] 77 b3 [2] 6c fd [2] 51 }

  condition:
    any of them
}