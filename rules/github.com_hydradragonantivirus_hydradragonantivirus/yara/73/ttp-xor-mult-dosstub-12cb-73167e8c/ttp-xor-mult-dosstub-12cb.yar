rule TTP_XOR_MULT_DOSStub_12cb {
  strings:
    $key_12cb = { 46 a3 [2] 32 bb [2] 75 b9 [2] 32 a8 [2] 7c a4 [2] 70 ae [2] 67 a5 [2] 7c eb [2] 41 }

  condition:
    any of them
}