rule TTP_XOR_MULT_DOSStub_7dcb {
  strings:
    $key_7dcb = { 29 a3 [2] 5d bb [2] 1a b9 [2] 5d a8 [2] 13 a4 [2] 1f ae [2] 08 a5 [2] 13 eb [2] 2e }

  condition:
    any of them
}