rule TTP_XOR_MULT_DOSStub_83d8 {
  strings:
    $key_83d8 = { d7 b0 [2] a3 a8 [2] e4 aa [2] a3 bb [2] ed b7 [2] e1 bd [2] f6 b6 [2] ed f8 [2] d0 }

  condition:
    any of them
}