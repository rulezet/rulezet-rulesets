rule TTP_XOR_MULT_DOSStub_f1a8 {
  strings:
    $key_f1a8 = { a5 c0 [2] d1 d8 [2] 96 da [2] d1 cb [2] 9f c7 [2] 93 cd [2] 84 c6 [2] 9f 88 [2] a2 }

  condition:
    any of them
}