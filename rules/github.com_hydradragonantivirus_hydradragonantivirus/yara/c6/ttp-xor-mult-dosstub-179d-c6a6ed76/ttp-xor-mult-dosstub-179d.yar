rule TTP_XOR_MULT_DOSStub_179d {
  strings:
    $key_179d = { 43 f5 [2] 37 ed [2] 70 ef [2] 37 fe [2] 79 f2 [2] 75 f8 [2] 62 f3 [2] 79 bd [2] 44 }

  condition:
    any of them
}