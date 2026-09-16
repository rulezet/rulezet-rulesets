rule TTP_XOR_MULT_DOSStub_f8ca {
  strings:
    $key_f8ca = { ac a2 [2] d8 ba [2] 9f b8 [2] d8 a9 [2] 96 a5 [2] 9a af [2] 8d a4 [2] 96 ea [2] ab }

  condition:
    any of them
}