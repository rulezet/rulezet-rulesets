rule TTP_XOR_MULT_DOSStub_4aa2 {
  strings:
    $key_4aa2 = { 1e ca [2] 6a d2 [2] 2d d0 [2] 6a c1 [2] 24 cd [2] 28 c7 [2] 3f cc [2] 24 82 [2] 19 }

  condition:
    any of them
}