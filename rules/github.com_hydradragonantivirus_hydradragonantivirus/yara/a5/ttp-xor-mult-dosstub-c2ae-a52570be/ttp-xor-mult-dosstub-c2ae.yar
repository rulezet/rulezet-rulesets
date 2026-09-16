rule TTP_XOR_MULT_DOSStub_c2ae {
  strings:
    $key_c2ae = { 96 c6 [2] e2 de [2] a5 dc [2] e2 cd [2] ac c1 [2] a0 cb [2] b7 c0 [2] ac 8e [2] 91 }

  condition:
    any of them
}