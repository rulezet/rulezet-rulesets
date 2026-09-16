rule TTP_XOR_MULT_DOSStub_049d {
  strings:
    $key_049d = { 50 f5 [2] 24 ed [2] 63 ef [2] 24 fe [2] 6a f2 [2] 66 f8 [2] 71 f3 [2] 6a bd [2] 57 }

  condition:
    any of them
}