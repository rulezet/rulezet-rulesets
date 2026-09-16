rule TTP_XOR_MULT_DOSStub_2885 {
  strings:
    $key_2885 = { 7c ed [2] 08 f5 [2] 4f f7 [2] 08 e6 [2] 46 ea [2] 4a e0 [2] 5d eb [2] 46 a5 [2] 7b }

  condition:
    any of them
}