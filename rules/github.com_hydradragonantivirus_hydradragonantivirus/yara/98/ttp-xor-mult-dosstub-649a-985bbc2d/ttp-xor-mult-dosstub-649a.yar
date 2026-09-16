rule TTP_XOR_MULT_DOSStub_649a {
  strings:
    $key_649a = { 30 f2 [2] 44 ea [2] 03 e8 [2] 44 f9 [2] 0a f5 [2] 06 ff [2] 11 f4 [2] 0a ba [2] 37 }

  condition:
    any of them
}