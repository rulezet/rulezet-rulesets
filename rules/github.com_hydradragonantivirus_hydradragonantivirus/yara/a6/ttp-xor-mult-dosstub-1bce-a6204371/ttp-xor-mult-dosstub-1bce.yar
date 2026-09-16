rule TTP_XOR_MULT_DOSStub_1bce {
  strings:
    $key_1bce = { 4f a6 [2] 3b be [2] 7c bc [2] 3b ad [2] 75 a1 [2] 79 ab [2] 6e a0 [2] 75 ee [2] 48 }

  condition:
    any of them
}