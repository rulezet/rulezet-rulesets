rule TTP_XOR_MULT_DOSStub_a8a9 {
  strings:
    $key_a8a9 = { fc c1 [2] 88 d9 [2] cf db [2] 88 ca [2] c6 c6 [2] ca cc [2] dd c7 [2] c6 89 [2] fb }

  condition:
    any of them
}