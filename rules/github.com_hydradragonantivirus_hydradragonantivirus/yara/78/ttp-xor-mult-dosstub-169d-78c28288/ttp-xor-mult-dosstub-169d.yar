rule TTP_XOR_MULT_DOSStub_169d {
  strings:
    $key_169d = { 42 f5 [2] 36 ed [2] 71 ef [2] 36 fe [2] 78 f2 [2] 74 f8 [2] 63 f3 [2] 78 bd [2] 45 }

  condition:
    any of them
}