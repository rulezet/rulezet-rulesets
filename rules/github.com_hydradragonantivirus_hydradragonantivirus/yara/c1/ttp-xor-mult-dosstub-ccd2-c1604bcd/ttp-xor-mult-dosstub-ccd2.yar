rule TTP_XOR_MULT_DOSStub_ccd2 {
  strings:
    $key_ccd2 = { 98 ba [2] ec a2 [2] ab a0 [2] ec b1 [2] a2 bd [2] ae b7 [2] b9 bc [2] a2 f2 [2] 9f }

  condition:
    any of them
}