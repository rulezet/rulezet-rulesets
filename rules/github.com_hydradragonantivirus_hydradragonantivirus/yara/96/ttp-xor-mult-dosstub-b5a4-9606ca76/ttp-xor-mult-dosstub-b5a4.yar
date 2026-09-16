rule TTP_XOR_MULT_DOSStub_b5a4 {
  strings:
    $key_b5a4 = { e1 cc [2] 95 d4 [2] d2 d6 [2] 95 c7 [2] db cb [2] d7 c1 [2] c0 ca [2] db 84 [2] e6 }

  condition:
    any of them
}