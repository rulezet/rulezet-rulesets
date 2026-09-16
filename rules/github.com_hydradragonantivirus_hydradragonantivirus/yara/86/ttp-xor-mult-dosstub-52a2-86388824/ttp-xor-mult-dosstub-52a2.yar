rule TTP_XOR_MULT_DOSStub_52a2 {
  strings:
    $key_52a2 = { 06 ca [2] 72 d2 [2] 35 d0 [2] 72 c1 [2] 3c cd [2] 30 c7 [2] 27 cc [2] 3c 82 [2] 01 }

  condition:
    any of them
}