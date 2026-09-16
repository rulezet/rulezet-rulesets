rule TTP_XOR_MULT_DOSStub_9a6c {
  strings:
    $key_9a6c = { ce 04 [2] ba 1c [2] fd 1e [2] ba 0f [2] f4 03 [2] f8 09 [2] ef 02 [2] f4 4c [2] c9 }

  condition:
    any of them
}