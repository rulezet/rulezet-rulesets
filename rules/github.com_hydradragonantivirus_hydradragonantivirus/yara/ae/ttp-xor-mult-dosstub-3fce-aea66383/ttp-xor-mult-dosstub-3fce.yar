rule TTP_XOR_MULT_DOSStub_3fce {
  strings:
    $key_3fce = { 6b a6 [2] 1f be [2] 58 bc [2] 1f ad [2] 51 a1 [2] 5d ab [2] 4a a0 [2] 51 ee [2] 6c }

  condition:
    any of them
}