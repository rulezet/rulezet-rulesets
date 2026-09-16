rule TTP_XOR_MULT_DOSStub_3db4 {
  strings:
    $key_3db4 = { 69 dc [2] 1d c4 [2] 5a c6 [2] 1d d7 [2] 53 db [2] 5f d1 [2] 48 da [2] 53 94 [2] 6e }

  condition:
    any of them
}