rule TTP_XOR_MULT_DOSStub_9a0c {
  strings:
    $key_9a0c = { ce 64 [2] ba 7c [2] fd 7e [2] ba 6f [2] f4 63 [2] f8 69 [2] ef 62 [2] f4 2c [2] c9 }

  condition:
    any of them
}