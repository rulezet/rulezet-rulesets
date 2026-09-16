rule TTP_XOR_MULT_DOSStub_439a {
  strings:
    $key_439a = { 17 f2 [2] 63 ea [2] 24 e8 [2] 63 f9 [2] 2d f5 [2] 21 ff [2] 36 f4 [2] 2d ba [2] 10 }

  condition:
    any of them
}