rule TTP_XOR_MULT_DOSStub_419d {
  strings:
    $key_419d = { 15 f5 [2] 61 ed [2] 26 ef [2] 61 fe [2] 2f f2 [2] 23 f8 [2] 34 f3 [2] 2f bd [2] 12 }

  condition:
    any of them
}