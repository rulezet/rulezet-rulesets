rule TTP_XOR_MULT_DOSStub_9a1f {
  strings:
    $key_9a1f = { ce 77 [2] ba 6f [2] fd 6d [2] ba 7c [2] f4 70 [2] f8 7a [2] ef 71 [2] f4 3f [2] c9 }

  condition:
    any of them
}