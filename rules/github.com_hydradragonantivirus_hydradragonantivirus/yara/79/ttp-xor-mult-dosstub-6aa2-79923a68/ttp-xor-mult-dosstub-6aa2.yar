rule TTP_XOR_MULT_DOSStub_6aa2 {
  strings:
    $key_6aa2 = { 3e ca [2] 4a d2 [2] 0d d0 [2] 4a c1 [2] 04 cd [2] 08 c7 [2] 1f cc [2] 04 82 [2] 39 }

  condition:
    any of them
}