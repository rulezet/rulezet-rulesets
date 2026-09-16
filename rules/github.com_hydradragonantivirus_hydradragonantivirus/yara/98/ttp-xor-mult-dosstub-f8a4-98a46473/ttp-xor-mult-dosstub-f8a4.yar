rule TTP_XOR_MULT_DOSStub_f8a4 {
  strings:
    $key_f8a4 = { ac cc [2] d8 d4 [2] 9f d6 [2] d8 c7 [2] 96 cb [2] 9a c1 [2] 8d ca [2] 96 84 [2] ab }

  condition:
    any of them
}