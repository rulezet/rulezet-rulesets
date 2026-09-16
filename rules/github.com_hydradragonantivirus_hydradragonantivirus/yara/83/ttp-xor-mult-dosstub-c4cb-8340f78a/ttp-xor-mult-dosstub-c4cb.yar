rule TTP_XOR_MULT_DOSStub_c4cb {
  strings:
    $key_c4cb = { 90 a3 [2] e4 bb [2] a3 b9 [2] e4 a8 [2] aa a4 [2] a6 ae [2] b1 a5 [2] aa eb [2] 97 }

  condition:
    any of them
}