rule TTP_XOR_MULT_DOSStub_b988 {
  strings:
    $key_b988 = { ed e0 [2] 99 f8 [2] de fa [2] 99 eb [2] d7 e7 [2] db ed [2] cc e6 [2] d7 a8 [2] ea }

  condition:
    any of them
}