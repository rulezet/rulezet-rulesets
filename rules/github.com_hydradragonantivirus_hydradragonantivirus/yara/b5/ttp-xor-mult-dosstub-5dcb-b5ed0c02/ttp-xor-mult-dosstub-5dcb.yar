rule TTP_XOR_MULT_DOSStub_5dcb {
  strings:
    $key_5dcb = { 09 a3 [2] 7d bb [2] 3a b9 [2] 7d a8 [2] 33 a4 [2] 3f ae [2] 28 a5 [2] 33 eb [2] 0e }

  condition:
    any of them
}