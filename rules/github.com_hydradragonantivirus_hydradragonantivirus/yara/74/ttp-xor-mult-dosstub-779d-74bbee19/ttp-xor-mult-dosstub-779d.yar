rule TTP_XOR_MULT_DOSStub_779d {
  strings:
    $key_779d = { 23 f5 [2] 57 ed [2] 10 ef [2] 57 fe [2] 19 f2 [2] 15 f8 [2] 02 f3 [2] 19 bd [2] 24 }

  condition:
    any of them
}