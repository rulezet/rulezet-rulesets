rule TTP_XOR_MULT_DOSStub_ccbb {
  strings:
    $key_ccbb = { 98 d3 [2] ec cb [2] ab c9 [2] ec d8 [2] a2 d4 [2] ae de [2] b9 d5 [2] a2 9b [2] 9f }

  condition:
    any of them
}