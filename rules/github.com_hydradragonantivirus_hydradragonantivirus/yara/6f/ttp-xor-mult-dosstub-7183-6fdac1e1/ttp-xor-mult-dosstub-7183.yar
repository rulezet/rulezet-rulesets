rule TTP_XOR_MULT_DOSStub_7183 {
  strings:
    $key_7183 = { 25 eb [2] 51 f3 [2] 16 f1 [2] 51 e0 [2] 1f ec [2] 13 e6 [2] 04 ed [2] 1f a3 [2] 22 }

  condition:
    any of them
}