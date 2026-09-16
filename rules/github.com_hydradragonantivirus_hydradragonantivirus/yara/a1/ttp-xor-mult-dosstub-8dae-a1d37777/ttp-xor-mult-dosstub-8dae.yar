rule TTP_XOR_MULT_DOSStub_8dae {
  strings:
    $key_8dae = { d9 c6 [2] ad de [2] ea dc [2] ad cd [2] e3 c1 [2] ef cb [2] f8 c0 [2] e3 8e [2] de }

  condition:
    any of them
}