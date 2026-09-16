rule TTP_XOR_MULT_DOSStub_f8b1 {
  strings:
    $key_f8b1 = { ac d9 [2] d8 c1 [2] 9f c3 [2] d8 d2 [2] 96 de [2] 9a d4 [2] 8d df [2] 96 91 [2] ab }

  condition:
    any of them
}