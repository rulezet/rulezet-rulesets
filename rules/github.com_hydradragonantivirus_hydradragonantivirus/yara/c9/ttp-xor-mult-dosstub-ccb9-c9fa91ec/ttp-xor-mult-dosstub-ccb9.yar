rule TTP_XOR_MULT_DOSStub_ccb9 {
  strings:
    $key_ccb9 = { 98 d1 [2] ec c9 [2] ab cb [2] ec da [2] a2 d6 [2] ae dc [2] b9 d7 [2] a2 99 [2] 9f }

  condition:
    any of them
}