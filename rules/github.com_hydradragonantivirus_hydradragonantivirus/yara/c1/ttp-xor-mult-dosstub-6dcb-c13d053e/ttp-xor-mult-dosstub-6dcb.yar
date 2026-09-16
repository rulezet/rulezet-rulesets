rule TTP_XOR_MULT_DOSStub_6dcb {
  strings:
    $key_6dcb = { 39 a3 [2] 4d bb [2] 0a b9 [2] 4d a8 [2] 03 a4 [2] 0f ae [2] 18 a5 [2] 03 eb [2] 3e }

  condition:
    any of them
}