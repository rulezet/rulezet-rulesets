rule TTP_XOR_MULT_DOSStub_1fca {
  strings:
    $key_1fca = { 4b a2 [2] 3f ba [2] 78 b8 [2] 3f a9 [2] 71 a5 [2] 7d af [2] 6a a4 [2] 71 ea [2] 4c }

  condition:
    any of them
}