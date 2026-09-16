rule TTP_XOR_MULT_DOSStub_9acd {
  strings:
    $key_9acd = { ce a5 [2] ba bd [2] fd bf [2] ba ae [2] f4 a2 [2] f8 a8 [2] ef a3 [2] f4 ed [2] c9 }

  condition:
    any of them
}