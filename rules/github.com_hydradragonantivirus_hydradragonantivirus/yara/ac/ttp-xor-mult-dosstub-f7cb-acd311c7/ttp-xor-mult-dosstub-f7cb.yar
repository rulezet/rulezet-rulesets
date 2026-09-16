rule TTP_XOR_MULT_DOSStub_f7cb {
  strings:
    $key_f7cb = { a3 a3 [2] d7 bb [2] 90 b9 [2] d7 a8 [2] 99 a4 [2] 95 ae [2] 82 a5 [2] 99 eb [2] a4 }

  condition:
    any of them
}