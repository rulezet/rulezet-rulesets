rule TTP_XOR_MULT_DOSStub_9baf {
  strings:
    $key_9baf = { cf c7 [2] bb df [2] fc dd [2] bb cc [2] f5 c0 [2] f9 ca [2] ee c1 [2] f5 8f [2] c8 }

  condition:
    any of them
}