rule TTP_XOR_MULT_DOSStub_58a2 {
  strings:
    $key_58a2 = { 0c ca [2] 78 d2 [2] 3f d0 [2] 78 c1 [2] 36 cd [2] 3a c7 [2] 2d cc [2] 36 82 [2] 0b }

  condition:
    any of them
}