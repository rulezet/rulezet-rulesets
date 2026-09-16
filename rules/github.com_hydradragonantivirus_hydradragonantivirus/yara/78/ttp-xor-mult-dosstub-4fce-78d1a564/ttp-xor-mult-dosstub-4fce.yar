rule TTP_XOR_MULT_DOSStub_4fce {
  strings:
    $key_4fce = { 1b a6 [2] 6f be [2] 28 bc [2] 6f ad [2] 21 a1 [2] 2d ab [2] 3a a0 [2] 21 ee [2] 1c }

  condition:
    any of them
}