rule TTP_XOR_MULT_DOSStub_29c1 {
  strings:
    $key_29c1 = { 7d a9 [2] 09 b1 [2] 4e b3 [2] 09 a2 [2] 47 ae [2] 4b a4 [2] 5c af [2] 47 e1 [2] 7a }

  condition:
    any of them
}