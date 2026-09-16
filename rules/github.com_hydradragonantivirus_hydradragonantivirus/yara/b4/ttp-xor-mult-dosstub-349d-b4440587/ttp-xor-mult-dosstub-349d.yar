rule TTP_XOR_MULT_DOSStub_349d {
  strings:
    $key_349d = { 60 f5 [2] 14 ed [2] 53 ef [2] 14 fe [2] 5a f2 [2] 56 f8 [2] 41 f3 [2] 5a bd [2] 67 }

  condition:
    any of them
}