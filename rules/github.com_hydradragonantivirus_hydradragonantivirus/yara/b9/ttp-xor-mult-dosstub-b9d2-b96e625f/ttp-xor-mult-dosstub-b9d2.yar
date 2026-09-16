rule TTP_XOR_MULT_DOSStub_b9d2 {
  strings:
    $key_b9d2 = { ed ba [2] 99 a2 [2] de a0 [2] 99 b1 [2] d7 bd [2] db b7 [2] cc bc [2] d7 f2 [2] ea }

  condition:
    any of them
}