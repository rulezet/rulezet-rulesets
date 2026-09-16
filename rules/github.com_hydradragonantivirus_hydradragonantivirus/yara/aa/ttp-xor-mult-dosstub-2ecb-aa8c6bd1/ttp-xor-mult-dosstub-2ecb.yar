rule TTP_XOR_MULT_DOSStub_2ecb {
  strings:
    $key_2ecb = { 7a a3 [2] 0e bb [2] 49 b9 [2] 0e a8 [2] 40 a4 [2] 4c ae [2] 5b a5 [2] 40 eb [2] 7d }

  condition:
    any of them
}