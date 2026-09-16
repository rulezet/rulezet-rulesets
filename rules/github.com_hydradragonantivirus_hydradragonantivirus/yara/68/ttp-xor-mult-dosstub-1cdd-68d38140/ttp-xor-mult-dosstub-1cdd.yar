rule TTP_XOR_MULT_DOSStub_1cdd {
  strings:
    $key_1cdd = { 48 b5 [2] 3c ad [2] 7b af [2] 3c be [2] 72 b2 [2] 7e b8 [2] 69 b3 [2] 72 fd [2] 4f }

  condition:
    any of them
}