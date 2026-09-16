rule TTP_XOR_MULT_DOSStub_82ae {
  strings:
    $key_82ae = { d6 c6 [2] a2 de [2] e5 dc [2] a2 cd [2] ec c1 [2] e0 cb [2] f7 c0 [2] ec 8e [2] d1 }

  condition:
    any of them
}