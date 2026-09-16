rule TTP_XOR_MULT_DOSStub_8ec3 {
  strings:
    $key_8ec3 = { da ab [2] ae b3 [2] e9 b1 [2] ae a0 [2] e0 ac [2] ec a6 [2] fb ad [2] e0 e3 [2] dd }

  condition:
    any of them
}