rule TTP_XOR_MULT_DOSStub_0ec6 {
  strings:
    $key_0ec6 = { 5a ae [2] 2e b6 [2] 69 b4 [2] 2e a5 [2] 60 a9 [2] 6c a3 [2] 7b a8 [2] 60 e6 [2] 5d }

  condition:
    any of them
}