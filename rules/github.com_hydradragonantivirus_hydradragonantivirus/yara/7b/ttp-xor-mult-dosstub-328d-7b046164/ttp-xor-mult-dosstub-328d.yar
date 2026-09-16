rule TTP_XOR_MULT_DOSStub_328d {
  strings:
    $key_328d = { 66 e5 [2] 12 fd [2] 55 ff [2] 12 ee [2] 5c e2 [2] 50 e8 [2] 47 e3 [2] 5c ad [2] 61 }

  condition:
    any of them
}