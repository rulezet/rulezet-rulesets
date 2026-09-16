rule TTP_XOR_MULT_DOSStub_ccc3 {
  strings:
    $key_ccc3 = { 98 ab [2] ec b3 [2] ab b1 [2] ec a0 [2] a2 ac [2] ae a6 [2] b9 ad [2] a2 e3 [2] 9f }

  condition:
    any of them
}