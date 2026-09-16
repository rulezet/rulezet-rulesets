rule TTP_XOR_MULT_DOSStub_1183 {
  strings:
    $key_1183 = { 45 eb [2] 31 f3 [2] 76 f1 [2] 31 e0 [2] 7f ec [2] 73 e6 [2] 64 ed [2] 7f a3 [2] 42 }

  condition:
    any of them
}