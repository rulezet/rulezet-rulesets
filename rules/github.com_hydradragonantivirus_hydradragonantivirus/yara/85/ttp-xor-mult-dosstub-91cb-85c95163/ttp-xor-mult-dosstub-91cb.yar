rule TTP_XOR_MULT_DOSStub_91cb {
  strings:
    $key_91cb = { c5 a3 [2] b1 bb [2] f6 b9 [2] b1 a8 [2] ff a4 [2] f3 ae [2] e4 a5 [2] ff eb [2] c2 }

  condition:
    any of them
}