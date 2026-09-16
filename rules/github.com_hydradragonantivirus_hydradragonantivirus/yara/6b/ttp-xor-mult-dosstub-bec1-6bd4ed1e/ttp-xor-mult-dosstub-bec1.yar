rule TTP_XOR_MULT_DOSStub_bec1 {
  strings:
    $key_bec1 = { ea a9 [2] 9e b1 [2] d9 b3 [2] 9e a2 [2] d0 ae [2] dc a4 [2] cb af [2] d0 e1 [2] ed }

  condition:
    any of them
}