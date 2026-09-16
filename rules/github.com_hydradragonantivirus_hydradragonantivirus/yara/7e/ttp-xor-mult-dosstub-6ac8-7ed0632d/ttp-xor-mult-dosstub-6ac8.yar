rule TTP_XOR_MULT_DOSStub_6ac8 {
  strings:
    $key_6ac8 = { 3e a0 [2] 4a b8 [2] 0d ba [2] 4a ab [2] 04 a7 [2] 08 ad [2] 1f a6 [2] 04 e8 [2] 39 }

  condition:
    any of them
}