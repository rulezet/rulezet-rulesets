rule TTP_XOR_MULT_DOSStub_00cb {
  strings:
    $key_00cb = { 54 a3 [2] 20 bb [2] 67 b9 [2] 20 a8 [2] 6e a4 [2] 62 ae [2] 75 a5 [2] 6e eb [2] 53 }

  condition:
    any of them
}