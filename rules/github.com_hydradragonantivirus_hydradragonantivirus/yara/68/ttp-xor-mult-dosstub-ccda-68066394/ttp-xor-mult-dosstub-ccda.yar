rule TTP_XOR_MULT_DOSStub_ccda {
  strings:
    $key_ccda = { 98 b2 [2] ec aa [2] ab a8 [2] ec b9 [2] a2 b5 [2] ae bf [2] b9 b4 [2] a2 fa [2] 9f }

  condition:
    any of them
}