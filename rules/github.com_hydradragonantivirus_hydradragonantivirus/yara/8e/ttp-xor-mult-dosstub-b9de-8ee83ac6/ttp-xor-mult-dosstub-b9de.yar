rule TTP_XOR_MULT_DOSStub_b9de {
  strings:
    $key_b9de = { ed b6 [2] 99 ae [2] de ac [2] 99 bd [2] d7 b1 [2] db bb [2] cc b0 [2] d7 fe [2] ea }

  condition:
    any of them
}