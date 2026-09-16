rule TTP_XOR_MULT_DOSStub_0fce {
  strings:
    $key_0fce = { 5b a6 [2] 2f be [2] 68 bc [2] 2f ad [2] 61 a1 [2] 6d ab [2] 7a a0 [2] 61 ee [2] 5c }

  condition:
    any of them
}