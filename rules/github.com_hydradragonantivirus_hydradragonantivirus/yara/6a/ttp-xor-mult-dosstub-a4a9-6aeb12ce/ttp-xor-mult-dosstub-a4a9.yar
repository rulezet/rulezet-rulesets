rule TTP_XOR_MULT_DOSStub_a4a9 {
  strings:
    $key_a4a9 = { f0 c1 [2] 84 d9 [2] c3 db [2] 84 ca [2] ca c6 [2] c6 cc [2] d1 c7 [2] ca 89 [2] f7 }

  condition:
    any of them
}