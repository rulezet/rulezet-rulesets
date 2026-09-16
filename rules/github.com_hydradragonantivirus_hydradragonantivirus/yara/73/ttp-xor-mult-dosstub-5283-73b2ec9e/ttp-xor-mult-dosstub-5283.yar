rule TTP_XOR_MULT_DOSStub_5283 {
  strings:
    $key_5283 = { 06 eb [2] 72 f3 [2] 35 f1 [2] 72 e0 [2] 3c ec [2] 30 e6 [2] 27 ed [2] 3c a3 [2] 01 }

  condition:
    any of them
}