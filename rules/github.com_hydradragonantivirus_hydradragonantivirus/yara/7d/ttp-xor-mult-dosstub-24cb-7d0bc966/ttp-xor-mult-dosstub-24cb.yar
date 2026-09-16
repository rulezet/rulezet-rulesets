rule TTP_XOR_MULT_DOSStub_24cb {
  strings:
    $key_24cb = { 70 a3 [2] 04 bb [2] 43 b9 [2] 04 a8 [2] 4a a4 [2] 46 ae [2] 51 a5 [2] 4a eb [2] 77 }

  condition:
    any of them
}