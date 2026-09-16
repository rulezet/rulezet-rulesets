rule TTP_XOR_MULT_DOSStub_f1ae {
  strings:
    $key_f1ae = { a5 c6 [2] d1 de [2] 96 dc [2] d1 cd [2] 9f c1 [2] 93 cb [2] 84 c0 [2] 9f 8e [2] a2 }

  condition:
    any of them
}