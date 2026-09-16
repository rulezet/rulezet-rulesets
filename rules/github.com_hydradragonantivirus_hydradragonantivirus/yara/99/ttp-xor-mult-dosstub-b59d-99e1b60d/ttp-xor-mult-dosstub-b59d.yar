rule TTP_XOR_MULT_DOSStub_b59d {
  strings:
    $key_b59d = { e1 f5 [2] 95 ed [2] d2 ef [2] 95 fe [2] db f2 [2] d7 f8 [2] c0 f3 [2] db bd [2] e6 }

  condition:
    any of them
}