rule TTP_XOR_MULT_DOSStub_37ca {
  strings:
    $key_37ca = { 63 a2 [2] 17 ba [2] 50 b8 [2] 17 a9 [2] 59 a5 [2] 55 af [2] 42 a4 [2] 59 ea [2] 64 }

  condition:
    any of them
}