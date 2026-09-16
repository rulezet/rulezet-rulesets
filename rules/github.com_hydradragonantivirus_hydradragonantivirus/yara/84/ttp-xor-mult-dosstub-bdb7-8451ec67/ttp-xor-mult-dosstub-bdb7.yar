rule TTP_XOR_MULT_DOSStub_bdb7 {
  strings:
    $key_bdb7 = { e9 df [2] 9d c7 [2] da c5 [2] 9d d4 [2] d3 d8 [2] df d2 [2] c8 d9 [2] d3 97 [2] ee }

  condition:
    any of them
}