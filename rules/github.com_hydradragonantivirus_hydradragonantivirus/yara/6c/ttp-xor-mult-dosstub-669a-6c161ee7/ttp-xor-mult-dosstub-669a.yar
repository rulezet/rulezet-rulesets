rule TTP_XOR_MULT_DOSStub_669a {
  strings:
    $key_669a = { 32 f2 [2] 46 ea [2] 01 e8 [2] 46 f9 [2] 08 f5 [2] 04 ff [2] 13 f4 [2] 08 ba [2] 35 }

  condition:
    any of them
}