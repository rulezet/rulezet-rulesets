rule TTP_XOR_MULT_DOSStub_9ae3 {
  strings:
    $key_9ae3 = { ce 8b [2] ba 93 [2] fd 91 [2] ba 80 [2] f4 8c [2] f8 86 [2] ef 8d [2] f4 c3 [2] c9 }

  condition:
    any of them
}