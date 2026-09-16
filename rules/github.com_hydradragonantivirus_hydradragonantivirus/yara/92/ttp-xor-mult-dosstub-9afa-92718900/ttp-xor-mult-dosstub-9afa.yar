rule TTP_XOR_MULT_DOSStub_9afa {
  strings:
    $key_9afa = { ce 92 [2] ba 8a [2] fd 88 [2] ba 99 [2] f4 95 [2] f8 9f [2] ef 94 [2] f4 da [2] c9 }

  condition:
    any of them
}