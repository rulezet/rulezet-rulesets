rule TTP_XOR_MULT_DOSStub_9a8d {
  strings:
    $key_9a8d = { ce e5 [2] ba fd [2] fd ff [2] ba ee [2] f4 e2 [2] f8 e8 [2] ef e3 [2] f4 ad [2] c9 }

  condition:
    any of them
}