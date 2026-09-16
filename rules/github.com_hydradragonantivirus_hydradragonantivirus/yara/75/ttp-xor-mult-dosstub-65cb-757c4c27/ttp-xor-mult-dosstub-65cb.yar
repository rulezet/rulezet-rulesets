rule TTP_XOR_MULT_DOSStub_65cb {
  strings:
    $key_65cb = { 31 a3 [2] 45 bb [2] 02 b9 [2] 45 a8 [2] 0b a4 [2] 07 ae [2] 10 a5 [2] 0b eb [2] 36 }

  condition:
    any of them
}