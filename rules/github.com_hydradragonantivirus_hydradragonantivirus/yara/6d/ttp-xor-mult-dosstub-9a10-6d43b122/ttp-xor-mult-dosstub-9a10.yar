rule TTP_XOR_MULT_DOSStub_9a10 {
  strings:
    $key_9a10 = { ce 78 [2] ba 60 [2] fd 62 [2] ba 73 [2] f4 7f [2] f8 75 [2] ef 7e [2] f4 30 [2] c9 }

  condition:
    any of them
}