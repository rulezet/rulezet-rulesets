rule TTP_XOR_MULT_DOSStub_039d {
  strings:
    $key_039d = { 57 f5 [2] 23 ed [2] 64 ef [2] 23 fe [2] 6d f2 [2] 61 f8 [2] 76 f3 [2] 6d bd [2] 50 }

  condition:
    any of them
}