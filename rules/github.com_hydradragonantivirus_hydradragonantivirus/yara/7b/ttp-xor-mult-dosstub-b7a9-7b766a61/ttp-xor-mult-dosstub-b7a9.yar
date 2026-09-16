rule TTP_XOR_MULT_DOSStub_b7a9 {
  strings:
    $key_b7a9 = { e3 c1 [2] 97 d9 [2] d0 db [2] 97 ca [2] d9 c6 [2] d5 cc [2] c2 c7 [2] d9 89 [2] e4 }

  condition:
    any of them
}