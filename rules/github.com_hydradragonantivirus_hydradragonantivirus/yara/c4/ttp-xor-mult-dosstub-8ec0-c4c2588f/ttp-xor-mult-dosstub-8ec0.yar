rule TTP_XOR_MULT_DOSStub_8ec0 {
  strings:
    $key_8ec0 = { da a8 [2] ae b0 [2] e9 b2 [2] ae a3 [2] e0 af [2] ec a5 [2] fb ae [2] e0 e0 [2] dd }

  condition:
    any of them
}