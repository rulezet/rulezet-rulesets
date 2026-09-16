rule TTP_XOR_MULT_DOSStub_309d {
  strings:
    $key_309d = { 64 f5 [2] 10 ed [2] 57 ef [2] 10 fe [2] 5e f2 [2] 52 f8 [2] 45 f3 [2] 5e bd [2] 63 }

  condition:
    any of them
}