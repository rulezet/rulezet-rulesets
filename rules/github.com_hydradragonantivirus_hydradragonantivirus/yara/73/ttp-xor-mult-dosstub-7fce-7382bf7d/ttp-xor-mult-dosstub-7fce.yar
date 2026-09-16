rule TTP_XOR_MULT_DOSStub_7fce {
  strings:
    $key_7fce = { 2b a6 [2] 5f be [2] 18 bc [2] 5f ad [2] 11 a1 [2] 1d ab [2] 0a a0 [2] 11 ee [2] 2c }

  condition:
    any of them
}