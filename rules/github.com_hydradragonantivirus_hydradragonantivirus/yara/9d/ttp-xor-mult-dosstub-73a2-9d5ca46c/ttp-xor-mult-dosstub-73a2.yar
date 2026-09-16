rule TTP_XOR_MULT_DOSStub_73a2 {
  strings:
    $key_73a2 = { 27 ca [2] 53 d2 [2] 14 d0 [2] 53 c1 [2] 1d cd [2] 11 c7 [2] 06 cc [2] 1d 82 [2] 20 }

  condition:
    any of them
}