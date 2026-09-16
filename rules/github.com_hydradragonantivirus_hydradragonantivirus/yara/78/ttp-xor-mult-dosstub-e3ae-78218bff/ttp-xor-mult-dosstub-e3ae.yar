rule TTP_XOR_MULT_DOSStub_e3ae {
  strings:
    $key_e3ae = { b7 c6 [2] c3 de [2] 84 dc [2] c3 cd [2] 8d c1 [2] 81 cb [2] 96 c0 [2] 8d 8e [2] b0 }

  condition:
    any of them
}