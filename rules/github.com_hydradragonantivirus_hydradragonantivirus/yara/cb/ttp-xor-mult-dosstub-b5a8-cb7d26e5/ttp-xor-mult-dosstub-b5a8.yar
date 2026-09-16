rule TTP_XOR_MULT_DOSStub_b5a8 {
  strings:
    $key_b5a8 = { e1 c0 [2] 95 d8 [2] d2 da [2] 95 cb [2] db c7 [2] d7 cd [2] c0 c6 [2] db 88 [2] e6 }

  condition:
    any of them
}