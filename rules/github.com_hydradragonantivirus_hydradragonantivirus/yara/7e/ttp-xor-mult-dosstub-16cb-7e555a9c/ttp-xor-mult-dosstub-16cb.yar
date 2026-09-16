rule TTP_XOR_MULT_DOSStub_16cb {
  strings:
    $key_16cb = { 42 a3 [2] 36 bb [2] 71 b9 [2] 36 a8 [2] 78 a4 [2] 74 ae [2] 63 a5 [2] 78 eb [2] 45 }

  condition:
    any of them
}