rule TTP_XOR_MULT_DOSStub_ccd6 {
  strings:
    $key_ccd6 = { 98 be [2] ec a6 [2] ab a4 [2] ec b5 [2] a2 b9 [2] ae b3 [2] b9 b8 [2] a2 f6 [2] 9f }

  condition:
    any of them
}