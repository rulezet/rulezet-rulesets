rule TTP_XOR_MULT_DOSStub_4cce {
  strings:
    $key_4cce = { 18 a6 [2] 6c be [2] 2b bc [2] 6c ad [2] 22 a1 [2] 2e ab [2] 39 a0 [2] 22 ee [2] 1f }

  condition:
    any of them
}