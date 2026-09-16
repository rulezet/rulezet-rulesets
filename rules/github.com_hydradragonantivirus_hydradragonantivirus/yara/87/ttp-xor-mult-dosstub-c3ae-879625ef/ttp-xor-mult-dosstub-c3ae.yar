rule TTP_XOR_MULT_DOSStub_c3ae {
  strings:
    $key_c3ae = { 97 c6 [2] e3 de [2] a4 dc [2] e3 cd [2] ad c1 [2] a1 cb [2] b6 c0 [2] ad 8e [2] 90 }

  condition:
    any of them
}