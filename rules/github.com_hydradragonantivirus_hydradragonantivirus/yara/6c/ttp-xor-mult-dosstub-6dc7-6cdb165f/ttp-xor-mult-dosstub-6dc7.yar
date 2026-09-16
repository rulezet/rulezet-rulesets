rule TTP_XOR_MULT_DOSStub_6dc7 {
  strings:
    $key_6dc7 = { 39 af [2] 4d b7 [2] 0a b5 [2] 4d a4 [2] 03 a8 [2] 0f a2 [2] 18 a9 [2] 03 e7 [2] 3e }

  condition:
    any of them
}