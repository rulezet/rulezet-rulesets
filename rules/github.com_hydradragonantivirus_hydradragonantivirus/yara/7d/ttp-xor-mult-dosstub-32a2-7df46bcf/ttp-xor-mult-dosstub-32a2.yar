rule TTP_XOR_MULT_DOSStub_32a2 {
  strings:
    $key_32a2 = { 66 ca [2] 12 d2 [2] 55 d0 [2] 12 c1 [2] 5c cd [2] 50 c7 [2] 47 cc [2] 5c 82 [2] 61 }

  condition:
    any of them
}