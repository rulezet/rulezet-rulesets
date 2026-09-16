rule TTP_XOR_MULT_DOSStub_96fe {
  strings:
    $key_96fe = { c2 96 [2] b6 8e [2] f1 8c [2] b6 9d [2] f8 91 [2] f4 9b [2] e3 90 [2] f8 de [2] c5 }

  condition:
    any of them
}