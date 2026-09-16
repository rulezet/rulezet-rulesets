rule TTP_XOR_MULT_DOSStub_6dc6 {
  strings:
    $key_6dc6 = { 39 ae [2] 4d b6 [2] 0a b4 [2] 4d a5 [2] 03 a9 [2] 0f a3 [2] 18 a8 [2] 03 e6 [2] 3e }

  condition:
    any of them
}