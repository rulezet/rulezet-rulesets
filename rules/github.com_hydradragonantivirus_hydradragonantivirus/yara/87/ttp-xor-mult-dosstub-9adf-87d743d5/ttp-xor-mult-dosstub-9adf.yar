rule TTP_XOR_MULT_DOSStub_9adf {
  strings:
    $key_9adf = { ce b7 [2] ba af [2] fd ad [2] ba bc [2] f4 b0 [2] f8 ba [2] ef b1 [2] f4 ff [2] c9 }

  condition:
    any of them
}