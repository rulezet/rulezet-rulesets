rule TTP_XOR_MULT_DOSStub_c69d {
  strings:
    $key_c69d = { 92 f5 [2] e6 ed [2] a1 ef [2] e6 fe [2] a8 f2 [2] a4 f8 [2] b3 f3 [2] a8 bd [2] 95 }

  condition:
    any of them
}