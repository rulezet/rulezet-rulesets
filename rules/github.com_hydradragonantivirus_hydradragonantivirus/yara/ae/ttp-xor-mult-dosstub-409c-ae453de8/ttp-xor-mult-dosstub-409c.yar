rule TTP_XOR_MULT_DOSStub_409c {
  strings:
    $key_409c = { 14 f4 [2] 60 ec [2] 27 ee [2] 60 ff [2] 2e f3 [2] 22 f9 [2] 35 f2 [2] 2e bc [2] 13 }

  condition:
    any of them
}