rule TTP_XOR_MULT_DOSStub_2bdf {
  strings:
    $key_2bdf = { 7f b7 [2] 0b af [2] 4c ad [2] 0b bc [2] 45 b0 [2] 49 ba [2] 5e b1 [2] 45 ff [2] 78 }

  condition:
    any of them
}