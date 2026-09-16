rule TTP_XOR_MULT_DOSStub_098d {
  strings:
    $key_098d = { 5d e5 [2] 29 fd [2] 6e ff [2] 29 ee [2] 67 e2 [2] 6b e8 [2] 7c e3 [2] 67 ad [2] 5a }

  condition:
    any of them
}