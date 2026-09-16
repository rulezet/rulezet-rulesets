rule TTP_XOR_MULT_DOSStub_ccab {
  strings:
    $key_ccab = { 98 c3 [2] ec db [2] ab d9 [2] ec c8 [2] a2 c4 [2] ae ce [2] b9 c5 [2] a2 8b [2] 9f }

  condition:
    any of them
}