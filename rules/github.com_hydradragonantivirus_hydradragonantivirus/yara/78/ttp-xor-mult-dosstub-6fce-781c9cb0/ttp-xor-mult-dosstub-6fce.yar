rule TTP_XOR_MULT_DOSStub_6fce {
  strings:
    $key_6fce = { 3b a6 [2] 4f be [2] 08 bc [2] 4f ad [2] 01 a1 [2] 0d ab [2] 1a a0 [2] 01 ee [2] 3c }

  condition:
    any of them
}