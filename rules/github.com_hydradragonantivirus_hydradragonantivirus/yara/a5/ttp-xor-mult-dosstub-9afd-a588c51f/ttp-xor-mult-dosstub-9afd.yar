rule TTP_XOR_MULT_DOSStub_9afd {
  strings:
    $key_9afd = { ce 95 [2] ba 8d [2] fd 8f [2] ba 9e [2] f4 92 [2] f8 98 [2] ef 93 [2] f4 dd [2] c9 }

  condition:
    any of them
}