rule TTP_XOR_MULT_DOSStub_9acb {
  strings:
    $key_9acb = { ce a3 [2] ba bb [2] fd b9 [2] ba a8 [2] f4 a4 [2] f8 ae [2] ef a5 [2] f4 eb [2] c9 }

  condition:
    any of them
}