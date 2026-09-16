rule TTP_XOR_MULT_DOSStub_b9df {
  strings:
    $key_b9df = { ed b7 [2] 99 af [2] de ad [2] 99 bc [2] d7 b0 [2] db ba [2] cc b1 [2] d7 ff [2] ea }

  condition:
    any of them
}