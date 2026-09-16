rule TTP_XOR_MULT_DOSStub_9bc4 {
  strings:
    $key_9bc4 = { cf ac [2] bb b4 [2] fc b6 [2] bb a7 [2] f5 ab [2] f9 a1 [2] ee aa [2] f5 e4 [2] c8 }

  condition:
    any of them
}