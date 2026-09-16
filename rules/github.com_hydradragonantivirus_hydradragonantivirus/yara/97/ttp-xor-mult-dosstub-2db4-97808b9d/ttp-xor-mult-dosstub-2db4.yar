rule TTP_XOR_MULT_DOSStub_2db4 {
  strings:
    $key_2db4 = { 79 dc [2] 0d c4 [2] 4a c6 [2] 0d d7 [2] 43 db [2] 4f d1 [2] 58 da [2] 43 94 [2] 7e }

  condition:
    any of them
}