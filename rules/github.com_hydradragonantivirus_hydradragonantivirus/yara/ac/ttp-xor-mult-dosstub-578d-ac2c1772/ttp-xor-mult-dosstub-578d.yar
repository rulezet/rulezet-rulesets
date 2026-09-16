rule TTP_XOR_MULT_DOSStub_578d {
  strings:
    $key_578d = { 03 e5 [2] 77 fd [2] 30 ff [2] 77 ee [2] 39 e2 [2] 35 e8 [2] 22 e3 [2] 39 ad [2] 04 }

  condition:
    any of them
}