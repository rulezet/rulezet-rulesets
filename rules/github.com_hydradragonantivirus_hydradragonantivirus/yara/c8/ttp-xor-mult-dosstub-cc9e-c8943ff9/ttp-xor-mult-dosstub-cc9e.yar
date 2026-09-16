rule TTP_XOR_MULT_DOSStub_cc9e {
  strings:
    $key_cc9e = { 98 f6 [2] ec ee [2] ab ec [2] ec fd [2] a2 f1 [2] ae fb [2] b9 f0 [2] a2 be [2] 9f }

  condition:
    any of them
}