rule TTP_XOR_MULT_DOSStub_c2cb {
  strings:
    $key_c2cb = { 96 a3 [2] e2 bb [2] a5 b9 [2] e2 a8 [2] ac a4 [2] a0 ae [2] b7 a5 [2] ac eb [2] 91 }

  condition:
    any of them
}