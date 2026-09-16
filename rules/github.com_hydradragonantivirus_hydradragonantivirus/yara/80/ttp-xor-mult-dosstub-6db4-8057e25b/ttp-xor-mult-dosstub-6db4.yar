rule TTP_XOR_MULT_DOSStub_6db4 {
  strings:
    $key_6db4 = { 39 dc [2] 4d c4 [2] 0a c6 [2] 4d d7 [2] 03 db [2] 0f d1 [2] 18 da [2] 03 94 [2] 3e }

  condition:
    any of them
}