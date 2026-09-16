rule TTP_XOR_MULT_DOSStub_9ae8 {
  strings:
    $key_9ae8 = { ce 80 [2] ba 98 [2] fd 9a [2] ba 8b [2] f4 87 [2] f8 8d [2] ef 86 [2] f4 c8 [2] c9 }

  condition:
    any of them
}