rule TTP_XOR_MULT_DOSStub_29c6 {
  strings:
    $key_29c6 = { 7d ae [2] 09 b6 [2] 4e b4 [2] 09 a5 [2] 47 a9 [2] 4b a3 [2] 5c a8 [2] 47 e6 [2] 7a }

  condition:
    any of them
}