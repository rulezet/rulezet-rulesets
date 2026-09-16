rule TTP_XOR_MULT_DOSStub_40cb {
  strings:
    $key_40cb = { 14 a3 [2] 60 bb [2] 27 b9 [2] 60 a8 [2] 2e a4 [2] 22 ae [2] 35 a5 [2] 2e eb [2] 13 }

  condition:
    any of them
}