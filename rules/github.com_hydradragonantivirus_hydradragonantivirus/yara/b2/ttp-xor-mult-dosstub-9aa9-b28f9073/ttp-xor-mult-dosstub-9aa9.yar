rule TTP_XOR_MULT_DOSStub_9aa9 {
  strings:
    $key_9aa9 = { ce c1 [2] ba d9 [2] fd db [2] ba ca [2] f4 c6 [2] f8 cc [2] ef c7 [2] f4 89 [2] c9 }

  condition:
    any of them
}