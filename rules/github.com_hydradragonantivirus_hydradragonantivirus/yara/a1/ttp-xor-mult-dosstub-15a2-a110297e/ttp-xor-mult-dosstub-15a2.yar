rule TTP_XOR_MULT_DOSStub_15a2 {
  strings:
    $key_15a2 = { 41 ca [2] 35 d2 [2] 72 d0 [2] 35 c1 [2] 7b cd [2] 77 c7 [2] 60 cc [2] 7b 82 [2] 46 }

  condition:
    any of them
}