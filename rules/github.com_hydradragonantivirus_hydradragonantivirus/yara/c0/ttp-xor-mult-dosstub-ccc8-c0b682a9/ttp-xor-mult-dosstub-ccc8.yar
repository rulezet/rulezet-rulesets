rule TTP_XOR_MULT_DOSStub_ccc8 {
  strings:
    $key_ccc8 = { 98 a0 [2] ec b8 [2] ab ba [2] ec ab [2] a2 a7 [2] ae ad [2] b9 a6 [2] a2 e8 [2] 9f }

  condition:
    any of them
}