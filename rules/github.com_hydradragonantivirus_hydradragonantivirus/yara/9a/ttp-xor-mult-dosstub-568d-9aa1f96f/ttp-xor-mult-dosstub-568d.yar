rule TTP_XOR_MULT_DOSStub_568d {
  strings:
    $key_568d = { 02 e5 [2] 76 fd [2] 31 ff [2] 76 ee [2] 38 e2 [2] 34 e8 [2] 23 e3 [2] 38 ad [2] 05 }

  condition:
    any of them
}