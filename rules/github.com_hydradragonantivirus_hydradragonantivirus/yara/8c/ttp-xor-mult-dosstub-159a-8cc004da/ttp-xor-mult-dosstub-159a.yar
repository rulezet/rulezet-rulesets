rule TTP_XOR_MULT_DOSStub_159a {
  strings:
    $key_159a = { 41 f2 [2] 35 ea [2] 72 e8 [2] 35 f9 [2] 7b f5 [2] 77 ff [2] 60 f4 [2] 7b ba [2] 46 }

  condition:
    any of them
}