rule TTP_XOR_MULT_DOSStub_9aed {
  strings:
    $key_9aed = { ce 85 [2] ba 9d [2] fd 9f [2] ba 8e [2] f4 82 [2] f8 88 [2] ef 83 [2] f4 cd [2] c9 }

  condition:
    any of them
}