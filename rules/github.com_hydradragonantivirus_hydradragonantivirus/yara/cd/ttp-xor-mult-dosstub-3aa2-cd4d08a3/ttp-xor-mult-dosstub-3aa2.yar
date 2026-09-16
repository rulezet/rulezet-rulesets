rule TTP_XOR_MULT_DOSStub_3aa2 {
  strings:
    $key_3aa2 = { 6e ca [2] 1a d2 [2] 5d d0 [2] 1a c1 [2] 54 cd [2] 58 c7 [2] 4f cc [2] 54 82 [2] 69 }

  condition:
    any of them
}