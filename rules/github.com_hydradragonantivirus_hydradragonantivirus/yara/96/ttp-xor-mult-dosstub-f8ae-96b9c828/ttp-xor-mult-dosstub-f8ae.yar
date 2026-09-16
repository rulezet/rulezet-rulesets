rule TTP_XOR_MULT_DOSStub_f8ae {
  strings:
    $key_f8ae = { ac c6 [2] d8 de [2] 9f dc [2] d8 cd [2] 96 c1 [2] 9a cb [2] 8d c0 [2] 96 8e [2] ab }

  condition:
    any of them
}