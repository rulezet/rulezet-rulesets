rule TTP_XOR_MULT_DOSStub_d3db {
  strings:
    $key_d3db = { 87 b3 [2] f3 ab [2] b4 a9 [2] f3 b8 [2] bd b4 [2] b1 be [2] a6 b5 [2] bd fb [2] 80 }

  condition:
    any of them
}