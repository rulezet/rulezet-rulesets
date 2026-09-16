rule TTP_XOR_MULT_DOSStub_749d {
  strings:
    $key_749d = { 20 f5 [2] 54 ed [2] 13 ef [2] 54 fe [2] 1a f2 [2] 16 f8 [2] 01 f3 [2] 1a bd [2] 27 }

  condition:
    any of them
}