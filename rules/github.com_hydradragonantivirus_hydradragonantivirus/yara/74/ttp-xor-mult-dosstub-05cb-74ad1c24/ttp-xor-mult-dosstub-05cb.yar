rule TTP_XOR_MULT_DOSStub_05cb {
  strings:
    $key_05cb = { 51 a3 [2] 25 bb [2] 62 b9 [2] 25 a8 [2] 6b a4 [2] 67 ae [2] 70 a5 [2] 6b eb [2] 56 }

  condition:
    any of them
}