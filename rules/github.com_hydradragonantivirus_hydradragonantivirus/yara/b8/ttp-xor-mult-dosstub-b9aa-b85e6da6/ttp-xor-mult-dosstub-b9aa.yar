rule TTP_XOR_MULT_DOSStub_b9aa {
  strings:
    $key_b9aa = { ed c2 [2] 99 da [2] de d8 [2] 99 c9 [2] d7 c5 [2] db cf [2] cc c4 [2] d7 8a [2] ea }

  condition:
    any of them
}