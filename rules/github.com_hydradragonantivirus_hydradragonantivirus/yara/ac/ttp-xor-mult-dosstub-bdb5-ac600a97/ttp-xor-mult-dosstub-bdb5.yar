rule TTP_XOR_MULT_DOSStub_bdb5 {
  strings:
    $key_bdb5 = { e9 dd [2] 9d c5 [2] da c7 [2] 9d d6 [2] d3 da [2] df d0 [2] c8 db [2] d3 95 [2] ee }

  condition:
    any of them
}