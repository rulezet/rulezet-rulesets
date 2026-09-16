rule TTP_XOR_MULT_DOSStub_449d {
  strings:
    $key_449d = { 10 f5 [2] 64 ed [2] 23 ef [2] 64 fe [2] 2a f2 [2] 26 f8 [2] 31 f3 [2] 2a bd [2] 17 }

  condition:
    any of them
}