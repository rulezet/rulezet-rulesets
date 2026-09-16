rule TTP_XOR_MULT_DOSStub_7283 {
  strings:
    $key_7283 = { 26 eb [2] 52 f3 [2] 15 f1 [2] 52 e0 [2] 1c ec [2] 10 e6 [2] 07 ed [2] 1c a3 [2] 21 }

  condition:
    any of them
}