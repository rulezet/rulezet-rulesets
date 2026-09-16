rule TTP_XOR_MULT_DOSStub_d99b {
  strings:
    $key_d99b = { 8d f3 [2] f9 eb [2] be e9 [2] f9 f8 [2] b7 f4 [2] bb fe [2] ac f5 [2] b7 bb [2] 8a }

  condition:
    any of them
}