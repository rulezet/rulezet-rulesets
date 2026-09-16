rule TTP_XOR_MULT_DOSStub_2cdd {
  strings:
    $key_2cdd = { 78 b5 [2] 0c ad [2] 4b af [2] 0c be [2] 42 b2 [2] 4e b8 [2] 59 b3 [2] 42 fd [2] 7f }

  condition:
    any of them
}