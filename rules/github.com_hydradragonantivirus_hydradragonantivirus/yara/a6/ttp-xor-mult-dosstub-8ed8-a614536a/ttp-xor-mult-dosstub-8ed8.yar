rule TTP_XOR_MULT_DOSStub_8ed8 {
  strings:
    $key_8ed8 = { da b0 [2] ae a8 [2] e9 aa [2] ae bb [2] e0 b7 [2] ec bd [2] fb b6 [2] e0 f8 [2] dd }

  condition:
    any of them
}