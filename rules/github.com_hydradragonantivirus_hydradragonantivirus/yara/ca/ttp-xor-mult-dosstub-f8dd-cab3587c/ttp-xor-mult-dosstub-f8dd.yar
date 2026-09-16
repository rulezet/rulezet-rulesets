rule TTP_XOR_MULT_DOSStub_f8dd {
  strings:
    $key_f8dd = { ac b5 [2] d8 ad [2] 9f af [2] d8 be [2] 96 b2 [2] 9a b8 [2] 8d b3 [2] 96 fd [2] ab }

  condition:
    any of them
}