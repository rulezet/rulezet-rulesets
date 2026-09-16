rule TTP_XOR_MULT_DOSStub_b5ae {
  strings:
    $key_b5ae = { e1 c6 [2] 95 de [2] d2 dc [2] 95 cd [2] db c1 [2] d7 cb [2] c0 c0 [2] db 8e [2] e6 }

  condition:
    any of them
}