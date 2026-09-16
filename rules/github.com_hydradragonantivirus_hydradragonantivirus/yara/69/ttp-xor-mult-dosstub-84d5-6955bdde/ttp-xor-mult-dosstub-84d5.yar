rule TTP_XOR_MULT_DOSStub_84d5 {
  strings:
    $key_84d5 = { d0 bd [2] a4 a5 [2] e3 a7 [2] a4 b6 [2] ea ba [2] e6 b0 [2] f1 bb [2] ea f5 [2] d7 }

  condition:
    any of them
}