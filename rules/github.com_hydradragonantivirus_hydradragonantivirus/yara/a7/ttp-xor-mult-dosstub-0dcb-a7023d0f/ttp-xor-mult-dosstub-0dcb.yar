rule TTP_XOR_MULT_DOSStub_0dcb {
  strings:
    $key_0dcb = { 59 a3 [2] 2d bb [2] 6a b9 [2] 2d a8 [2] 63 a4 [2] 6f ae [2] 78 a5 [2] 63 eb [2] 5e }

  condition:
    any of them
}