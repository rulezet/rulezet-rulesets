rule TTP_XOR_MULT_DOSStub_2fce {
  strings:
    $key_2fce = { 7b a6 [2] 0f be [2] 48 bc [2] 0f ad [2] 41 a1 [2] 4d ab [2] 5a a0 [2] 41 ee [2] 7c }

  condition:
    any of them
}