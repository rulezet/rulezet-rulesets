rule TTP_XOR_MULT_DOSStub_cdd9 {
  strings:
    $key_cdd9 = { 99 b1 [2] ed a9 [2] aa ab [2] ed ba [2] a3 b6 [2] af bc [2] b8 b7 [2] a3 f9 [2] 9e }

  condition:
    any of them
}