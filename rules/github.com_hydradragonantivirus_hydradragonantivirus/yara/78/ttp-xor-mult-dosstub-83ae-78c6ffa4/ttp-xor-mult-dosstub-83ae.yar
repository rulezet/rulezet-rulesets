rule TTP_XOR_MULT_DOSStub_83ae {
  strings:
    $key_83ae = { d7 c6 [2] a3 de [2] e4 dc [2] a3 cd [2] ed c1 [2] e1 cb [2] f6 c0 [2] ed 8e [2] d0 }

  condition:
    any of them
}