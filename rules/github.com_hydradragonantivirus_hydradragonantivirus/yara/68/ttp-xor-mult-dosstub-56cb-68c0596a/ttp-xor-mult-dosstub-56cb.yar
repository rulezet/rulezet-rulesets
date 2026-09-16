rule TTP_XOR_MULT_DOSStub_56cb {
  strings:
    $key_56cb = { 02 a3 [2] 76 bb [2] 31 b9 [2] 76 a8 [2] 38 a4 [2] 34 ae [2] 23 a5 [2] 38 eb [2] 05 }

  condition:
    any of them
}