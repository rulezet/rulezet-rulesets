rule TTP_XOR_MULT_DOSStub_84d8 {
  strings:
    $key_84d8 = { d0 b0 [2] a4 a8 [2] e3 aa [2] a4 bb [2] ea b7 [2] e6 bd [2] f1 b6 [2] ea f8 [2] d7 }

  condition:
    any of them
}