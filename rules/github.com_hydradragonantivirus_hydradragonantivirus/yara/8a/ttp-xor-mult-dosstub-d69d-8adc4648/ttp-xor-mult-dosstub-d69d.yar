rule TTP_XOR_MULT_DOSStub_d69d {
  strings:
    $key_d69d = { 82 f5 [2] f6 ed [2] b1 ef [2] f6 fe [2] b8 f2 [2] b4 f8 [2] a3 f3 [2] b8 bd [2] 85 }

  condition:
    any of them
}