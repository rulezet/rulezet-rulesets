rule TTP_XOR_MULT_DOSStub_0283 {
  strings:
    $key_0283 = { 56 eb [2] 22 f3 [2] 65 f1 [2] 22 e0 [2] 6c ec [2] 60 e6 [2] 77 ed [2] 6c a3 [2] 51 }

  condition:
    any of them
}