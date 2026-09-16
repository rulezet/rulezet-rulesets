rule TTP_XOR_MULT_DOSStub_3283 {
  strings:
    $key_3283 = { 66 eb [2] 12 f3 [2] 55 f1 [2] 12 e0 [2] 5c ec [2] 50 e6 [2] 47 ed [2] 5c a3 [2] 61 }

  condition:
    any of them
}