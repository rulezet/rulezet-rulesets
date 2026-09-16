rule TTP_XOR_MULT_DOSStub_9a2b {
  strings:
    $key_9a2b = { ce 43 [2] ba 5b [2] fd 59 [2] ba 48 [2] f4 44 [2] f8 4e [2] ef 45 [2] f4 0b [2] c9 }

  condition:
    any of them
}