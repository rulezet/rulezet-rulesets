rule TTP_XOR_MULT_DOSStub_b9ab {
  strings:
    $key_b9ab = { ed c3 [2] 99 db [2] de d9 [2] 99 c8 [2] d7 c4 [2] db ce [2] cc c5 [2] d7 8b [2] ea }

  condition:
    any of them
}