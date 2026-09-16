rule TTP_XOR_MULT_DOSStub_5183 {
  strings:
    $key_5183 = { 05 eb [2] 71 f3 [2] 36 f1 [2] 71 e0 [2] 3f ec [2] 33 e6 [2] 24 ed [2] 3f a3 [2] 02 }

  condition:
    any of them
}