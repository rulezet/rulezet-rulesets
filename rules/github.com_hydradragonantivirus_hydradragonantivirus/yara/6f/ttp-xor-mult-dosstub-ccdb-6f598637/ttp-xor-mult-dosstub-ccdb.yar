rule TTP_XOR_MULT_DOSStub_ccdb {
  strings:
    $key_ccdb = { 98 b3 [2] ec ab [2] ab a9 [2] ec b8 [2] a2 b4 [2] ae be [2] b9 b5 [2] a2 fb [2] 9f }

  condition:
    any of them
}