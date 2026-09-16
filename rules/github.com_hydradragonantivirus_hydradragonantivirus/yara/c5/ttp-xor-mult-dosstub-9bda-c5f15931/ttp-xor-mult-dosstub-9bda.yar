rule TTP_XOR_MULT_DOSStub_9bda {
  strings:
    $key_9bda = { cf b2 [2] bb aa [2] fc a8 [2] bb b9 [2] f5 b5 [2] f9 bf [2] ee b4 [2] f5 fa [2] c8 }

  condition:
    any of them
}