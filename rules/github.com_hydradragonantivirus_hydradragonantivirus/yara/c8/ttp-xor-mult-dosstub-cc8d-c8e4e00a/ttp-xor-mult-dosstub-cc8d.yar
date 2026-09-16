rule TTP_XOR_MULT_DOSStub_cc8d {
  strings:
    $key_cc8d = { 98 e5 [2] ec fd [2] ab ff [2] ec ee [2] a2 e2 [2] ae e8 [2] b9 e3 [2] a2 ad [2] 9f }

  condition:
    any of them
}