rule TTP_XOR_MULT_DOSStub_8cae {
  strings:
    $key_8cae = { d8 c6 [2] ac de [2] eb dc [2] ac cd [2] e2 c1 [2] ee cb [2] f9 c0 [2] e2 8e [2] df }

  condition:
    any of them
}