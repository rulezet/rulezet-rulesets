rule TTP_XOR_MULT_DOSStub_b9ce {
  strings:
    $key_b9ce = { ed a6 [2] 99 be [2] de bc [2] 99 ad [2] d7 a1 [2] db ab [2] cc a0 [2] d7 ee [2] ea }

  condition:
    any of them
}