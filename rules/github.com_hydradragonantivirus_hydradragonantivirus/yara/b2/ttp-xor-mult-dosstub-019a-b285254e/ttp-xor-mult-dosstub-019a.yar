rule TTP_XOR_MULT_DOSStub_019a {
  strings:
    $key_019a = { 55 f2 [2] 21 ea [2] 66 e8 [2] 21 f9 [2] 6f f5 [2] 63 ff [2] 74 f4 [2] 6f ba [2] 52 }

  condition:
    any of them
}