rule TTP_XOR_MULT_DOSStub_9aac {
  strings:
    $key_9aac = { ce c4 [2] ba dc [2] fd de [2] ba cf [2] f4 c3 [2] f8 c9 [2] ef c2 [2] f4 8c [2] c9 }

  condition:
    any of them
}