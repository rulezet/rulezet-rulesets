rule TTP_XOR_MULT_DOSStub_9afb {
  strings:
    $key_9afb = { ce 93 [2] ba 8b [2] fd 89 [2] ba 98 [2] f4 94 [2] f8 9e [2] ef 95 [2] f4 db [2] c9 }

  condition:
    any of them
}