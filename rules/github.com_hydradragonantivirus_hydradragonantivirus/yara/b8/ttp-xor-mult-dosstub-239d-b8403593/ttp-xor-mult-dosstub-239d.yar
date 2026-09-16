rule TTP_XOR_MULT_DOSStub_239d {
  strings:
    $key_239d = { 77 f5 [2] 03 ed [2] 44 ef [2] 03 fe [2] 4d f2 [2] 41 f8 [2] 56 f3 [2] 4d bd [2] 70 }

  condition:
    any of them
}