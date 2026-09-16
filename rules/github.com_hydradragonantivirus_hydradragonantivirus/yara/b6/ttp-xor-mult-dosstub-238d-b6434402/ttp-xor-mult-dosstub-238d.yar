rule TTP_XOR_MULT_DOSStub_238d {
  strings:
    $key_238d = { 77 e5 [2] 03 fd [2] 44 ff [2] 03 ee [2] 4d e2 [2] 41 e8 [2] 56 e3 [2] 4d ad [2] 70 }

  condition:
    any of them
}