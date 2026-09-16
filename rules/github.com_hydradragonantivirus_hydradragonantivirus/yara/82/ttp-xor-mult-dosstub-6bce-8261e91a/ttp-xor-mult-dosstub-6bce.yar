rule TTP_XOR_MULT_DOSStub_6bce {
  strings:
    $key_6bce = { 3f a6 [2] 4b be [2] 0c bc [2] 4b ad [2] 05 a1 [2] 09 ab [2] 1e a0 [2] 05 ee [2] 38 }

  condition:
    any of them
}