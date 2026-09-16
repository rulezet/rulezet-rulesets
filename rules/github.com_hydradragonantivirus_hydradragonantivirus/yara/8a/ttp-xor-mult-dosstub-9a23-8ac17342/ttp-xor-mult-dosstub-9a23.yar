rule TTP_XOR_MULT_DOSStub_9a23 {
  strings:
    $key_9a23 = { ce 4b [2] ba 53 [2] fd 51 [2] ba 40 [2] f4 4c [2] f8 46 [2] ef 4d [2] f4 03 [2] c9 }

  condition:
    any of them
}