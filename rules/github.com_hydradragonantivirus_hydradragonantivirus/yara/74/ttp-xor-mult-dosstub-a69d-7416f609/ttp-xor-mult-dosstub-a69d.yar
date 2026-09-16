rule TTP_XOR_MULT_DOSStub_a69d {
  strings:
    $key_a69d = { f2 f5 [2] 86 ed [2] c1 ef [2] 86 fe [2] c8 f2 [2] c4 f8 [2] d3 f3 [2] c8 bd [2] f5 }

  condition:
    any of them
}