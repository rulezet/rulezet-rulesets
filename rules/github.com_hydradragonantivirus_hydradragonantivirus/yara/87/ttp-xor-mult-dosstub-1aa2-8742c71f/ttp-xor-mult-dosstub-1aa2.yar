rule TTP_XOR_MULT_DOSStub_1aa2 {
  strings:
    $key_1aa2 = { 4e ca [2] 3a d2 [2] 7d d0 [2] 3a c1 [2] 74 cd [2] 78 c7 [2] 6f cc [2] 74 82 [2] 49 }

  condition:
    any of them
}