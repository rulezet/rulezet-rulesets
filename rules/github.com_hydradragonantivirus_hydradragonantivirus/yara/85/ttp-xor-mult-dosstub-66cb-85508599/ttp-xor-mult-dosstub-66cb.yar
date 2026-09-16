rule TTP_XOR_MULT_DOSStub_66cb {
  strings:
    $key_66cb = { 32 a3 [2] 46 bb [2] 01 b9 [2] 46 a8 [2] 08 a4 [2] 04 ae [2] 13 a5 [2] 08 eb [2] 35 }

  condition:
    any of them
}