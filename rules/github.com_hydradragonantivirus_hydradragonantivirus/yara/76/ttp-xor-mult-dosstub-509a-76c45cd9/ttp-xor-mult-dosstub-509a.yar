rule TTP_XOR_MULT_DOSStub_509a {
  strings:
    $key_509a = { 04 f2 [2] 70 ea [2] 37 e8 [2] 70 f9 [2] 3e f5 [2] 32 ff [2] 25 f4 [2] 3e ba [2] 03 }

  condition:
    any of them
}