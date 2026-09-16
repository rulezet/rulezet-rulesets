rule TTP_XOR_MULT_DOSStub_e69d {
  strings:
    $key_e69d = { b2 f5 [2] c6 ed [2] 81 ef [2] c6 fe [2] 88 f2 [2] 84 f8 [2] 93 f3 [2] 88 bd [2] b5 }

  condition:
    any of them
}