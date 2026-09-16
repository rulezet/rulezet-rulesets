rule TTP_XOR_MULT_DOSStub_95ae {
  strings:
    $key_95ae = { c1 c6 [2] b5 de [2] f2 dc [2] b5 cd [2] fb c1 [2] f7 cb [2] e0 c0 [2] fb 8e [2] c6 }

  condition:
    any of them
}