rule TTP_XOR_MULT_DOSStub_b9d7 {
  strings:
    $key_b9d7 = { ed bf [2] 99 a7 [2] de a5 [2] 99 b4 [2] d7 b8 [2] db b2 [2] cc b9 [2] d7 f7 [2] ea }

  condition:
    any of them
}