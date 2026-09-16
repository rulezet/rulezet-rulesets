rule TTP_XOR_MULT_DOSStub_9af3 {
  strings:
    $key_9af3 = { ce 9b [2] ba 83 [2] fd 81 [2] ba 90 [2] f4 9c [2] f8 96 [2] ef 9d [2] f4 d3 [2] c9 }

  condition:
    any of them
}