rule TTP_XOR_MULT_DOSStub_1fce {
  strings:
    $key_1fce = { 4b a6 [2] 3f be [2] 78 bc [2] 3f ad [2] 71 a1 [2] 7d ab [2] 6a a0 [2] 71 ee [2] 4c }

  condition:
    any of them
}