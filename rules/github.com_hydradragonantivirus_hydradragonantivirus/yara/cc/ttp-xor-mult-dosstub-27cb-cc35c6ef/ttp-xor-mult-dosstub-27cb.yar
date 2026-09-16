rule TTP_XOR_MULT_DOSStub_27cb {
  strings:
    $key_27cb = { 73 a3 [2] 07 bb [2] 40 b9 [2] 07 a8 [2] 49 a4 [2] 45 ae [2] 52 a5 [2] 49 eb [2] 74 }

  condition:
    any of them
}