rule TTP_XOR_MULT_DOSStub_9bbe {
  strings:
    $key_9bbe = { cf d6 [2] bb ce [2] fc cc [2] bb dd [2] f5 d1 [2] f9 db [2] ee d0 [2] f5 9e [2] c8 }

  condition:
    any of them
}