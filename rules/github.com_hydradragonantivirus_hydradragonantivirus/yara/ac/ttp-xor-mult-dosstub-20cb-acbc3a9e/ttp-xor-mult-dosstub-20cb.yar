rule TTP_XOR_MULT_DOSStub_20cb {
  strings:
    $key_20cb = { 74 a3 [2] 00 bb [2] 47 b9 [2] 00 a8 [2] 4e a4 [2] 42 ae [2] 55 a5 [2] 4e eb [2] 73 }

  condition:
    any of them
}