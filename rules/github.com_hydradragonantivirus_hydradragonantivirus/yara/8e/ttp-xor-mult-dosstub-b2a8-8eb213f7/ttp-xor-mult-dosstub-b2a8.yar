rule TTP_XOR_MULT_DOSStub_b2a8 {
  strings:
    $key_b2a8 = { e6 c0 [2] 92 d8 [2] d5 da [2] 92 cb [2] dc c7 [2] d0 cd [2] c7 c6 [2] dc 88 [2] e1 }

  condition:
    any of them
}