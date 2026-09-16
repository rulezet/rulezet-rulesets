rule TTP_XOR_MULT_DOSStub_719d {
  strings:
    $key_719d = { 25 f5 [2] 51 ed [2] 16 ef [2] 51 fe [2] 1f f2 [2] 13 f8 [2] 04 f3 [2] 1f bd [2] 22 }

  condition:
    any of them
}