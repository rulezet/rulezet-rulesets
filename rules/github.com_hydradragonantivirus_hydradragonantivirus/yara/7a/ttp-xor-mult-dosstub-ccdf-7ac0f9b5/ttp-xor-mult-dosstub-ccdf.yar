rule TTP_XOR_MULT_DOSStub_ccdf {
  strings:
    $key_ccdf = { 98 b7 [2] ec af [2] ab ad [2] ec bc [2] a2 b0 [2] ae ba [2] b9 b1 [2] a2 ff [2] 9f }

  condition:
    any of them
}