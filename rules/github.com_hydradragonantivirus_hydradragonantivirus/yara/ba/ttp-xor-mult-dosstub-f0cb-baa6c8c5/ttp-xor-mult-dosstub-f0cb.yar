rule TTP_XOR_MULT_DOSStub_f0cb {
  strings:
    $key_f0cb = { a4 a3 [2] d0 bb [2] 97 b9 [2] d0 a8 [2] 9e a4 [2] 92 ae [2] 85 a5 [2] 9e eb [2] a3 }

  condition:
    any of them
}