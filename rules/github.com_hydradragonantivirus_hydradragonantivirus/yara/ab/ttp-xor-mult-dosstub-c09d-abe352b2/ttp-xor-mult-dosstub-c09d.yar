rule TTP_XOR_MULT_DOSStub_c09d {
  strings:
    $key_c09d = { 94 f5 [2] e0 ed [2] a7 ef [2] e0 fe [2] ae f2 [2] a2 f8 [2] b5 f3 [2] ae bd [2] 93 }

  condition:
    any of them
}