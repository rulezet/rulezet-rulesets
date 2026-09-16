rule TTP_XOR_MULT_DOSStub_8e98 {
  strings:
    $key_8e98 = { da f0 [2] ae e8 [2] e9 ea [2] ae fb [2] e0 f7 [2] ec fd [2] fb f6 [2] e0 b8 [2] dd }

  condition:
    any of them
}