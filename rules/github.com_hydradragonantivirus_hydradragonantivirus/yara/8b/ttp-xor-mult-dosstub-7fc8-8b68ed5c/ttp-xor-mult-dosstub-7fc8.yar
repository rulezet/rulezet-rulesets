rule TTP_XOR_MULT_DOSStub_7fc8 {
  strings:
    $key_7fc8 = { 2b a0 [2] 5f b8 [2] 18 ba [2] 5f ab [2] 11 a7 [2] 1d ad [2] 0a a6 [2] 11 e8 [2] 2c }

  condition:
    any of them
}