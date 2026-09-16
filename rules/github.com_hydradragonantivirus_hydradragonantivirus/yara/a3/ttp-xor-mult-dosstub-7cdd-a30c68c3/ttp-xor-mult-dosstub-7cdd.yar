rule TTP_XOR_MULT_DOSStub_7cdd {
  strings:
    $key_7cdd = { 28 b5 [2] 5c ad [2] 1b af [2] 5c be [2] 12 b2 [2] 1e b8 [2] 09 b3 [2] 12 fd [2] 2f }

  condition:
    any of them
}