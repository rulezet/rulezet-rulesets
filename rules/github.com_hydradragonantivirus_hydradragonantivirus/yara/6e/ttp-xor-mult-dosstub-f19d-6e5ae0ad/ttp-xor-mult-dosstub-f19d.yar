rule TTP_XOR_MULT_DOSStub_f19d {
  strings:
    $key_f19d = { a5 f5 [2] d1 ed [2] 96 ef [2] d1 fe [2] 9f f2 [2] 93 f8 [2] 84 f3 [2] 9f bd [2] a2 }

  condition:
    any of them
}