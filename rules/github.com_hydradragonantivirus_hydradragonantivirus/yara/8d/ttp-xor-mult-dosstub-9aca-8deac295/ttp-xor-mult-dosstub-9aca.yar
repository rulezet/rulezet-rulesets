rule TTP_XOR_MULT_DOSStub_9aca {
  strings:
    $key_9aca = { ce a2 [2] ba ba [2] fd b8 [2] ba a9 [2] f4 a5 [2] f8 af [2] ef a4 [2] f4 ea [2] c9 }

  condition:
    any of them
}