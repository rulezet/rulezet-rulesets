rule TTP_XOR_MULT_DOSStub_64a2 {
  strings:
    $key_64a2 = { 30 ca [2] 44 d2 [2] 03 d0 [2] 44 c1 [2] 0a cd [2] 06 c7 [2] 11 cc [2] 0a 82 [2] 37 }

  condition:
    any of them
}