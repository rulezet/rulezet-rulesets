rule TTP_XOR_MULT_DOSStub_b9d5 {
  strings:
    $key_b9d5 = { ed bd [2] 99 a5 [2] de a7 [2] 99 b6 [2] d7 ba [2] db b0 [2] cc bb [2] d7 f5 [2] ea }

  condition:
    any of them
}