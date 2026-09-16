rule TTP_XOR_MULT_DOSStub_34cb {
  strings:
    $key_34cb = { 60 a3 [2] 14 bb [2] 53 b9 [2] 14 a8 [2] 5a a4 [2] 56 ae [2] 41 a5 [2] 5a eb [2] 67 }

  condition:
    any of them
}