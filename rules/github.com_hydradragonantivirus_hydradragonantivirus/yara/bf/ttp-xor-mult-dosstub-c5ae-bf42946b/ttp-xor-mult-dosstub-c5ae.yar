rule TTP_XOR_MULT_DOSStub_c5ae {
  strings:
    $key_c5ae = { 91 c6 [2] e5 de [2] a2 dc [2] e5 cd [2] ab c1 [2] a7 cb [2] b0 c0 [2] ab 8e [2] 96 }

  condition:
    any of them
}