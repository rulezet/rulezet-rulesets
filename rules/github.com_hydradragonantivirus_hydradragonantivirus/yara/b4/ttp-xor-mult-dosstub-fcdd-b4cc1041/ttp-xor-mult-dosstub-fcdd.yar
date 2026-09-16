rule TTP_XOR_MULT_DOSStub_fcdd {
  strings:
    $key_fcdd = { a8 b5 [2] dc ad [2] 9b af [2] dc be [2] 92 b2 [2] 9e b8 [2] 89 b3 [2] 92 fd [2] af }

  condition:
    any of them
}