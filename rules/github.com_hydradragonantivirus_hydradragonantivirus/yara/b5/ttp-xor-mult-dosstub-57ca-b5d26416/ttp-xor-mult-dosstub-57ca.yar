rule TTP_XOR_MULT_DOSStub_57ca {
  strings:
    $key_57ca = { 03 a2 [2] 77 ba [2] 30 b8 [2] 77 a9 [2] 39 a5 [2] 35 af [2] 22 a4 [2] 39 ea [2] 04 }

  condition:
    any of them
}