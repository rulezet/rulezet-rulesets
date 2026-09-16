rule TTP_XOR_MULT_DOSStub_ccd4 {
  strings:
    $key_ccd4 = { 98 bc [2] ec a4 [2] ab a6 [2] ec b7 [2] a2 bb [2] ae b1 [2] b9 ba [2] a2 f4 [2] 9f }

  condition:
    any of them
}