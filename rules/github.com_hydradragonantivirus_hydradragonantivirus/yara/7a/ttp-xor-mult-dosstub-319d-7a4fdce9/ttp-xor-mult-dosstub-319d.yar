rule TTP_XOR_MULT_DOSStub_319d {
  strings:
    $key_319d = { 65 f5 [2] 11 ed [2] 56 ef [2] 11 fe [2] 5f f2 [2] 53 f8 [2] 44 f3 [2] 5f bd [2] 62 }

  condition:
    any of them
}