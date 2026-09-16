rule TTP_XOR_MULT_DOSStub_9bb7 {
  strings:
    $key_9bb7 = { cf df [2] bb c7 [2] fc c5 [2] bb d4 [2] f5 d8 [2] f9 d2 [2] ee d9 [2] f5 97 [2] c8 }

  condition:
    any of them
}