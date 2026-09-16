rule TTP_XOR_MULT_DOSStub_b9cb {
  strings:
    $key_b9cb = { ed a3 [2] 99 bb [2] de b9 [2] 99 a8 [2] d7 a4 [2] db ae [2] cc a5 [2] d7 eb [2] ea }

  condition:
    any of them
}