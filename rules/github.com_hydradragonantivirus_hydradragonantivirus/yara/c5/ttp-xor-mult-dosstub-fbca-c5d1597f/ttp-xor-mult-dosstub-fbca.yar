rule TTP_XOR_MULT_DOSStub_fbca {
  strings:
    $key_fbca = { af a2 [2] db ba [2] 9c b8 [2] db a9 [2] 95 a5 [2] 99 af [2] 8e a4 [2] 95 ea [2] a8 }

  condition:
    any of them
}