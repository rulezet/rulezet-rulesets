rule TTP_XOR_MULT_DOSStub_ccd7 {
  strings:
    $key_ccd7 = { 98 bf [2] ec a7 [2] ab a5 [2] ec b4 [2] a2 b8 [2] ae b2 [2] b9 b9 [2] a2 f7 [2] 9f }

  condition:
    any of them
}