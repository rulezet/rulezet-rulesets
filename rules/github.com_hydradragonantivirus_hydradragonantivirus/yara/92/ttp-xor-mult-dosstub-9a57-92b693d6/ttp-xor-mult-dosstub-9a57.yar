rule TTP_XOR_MULT_DOSStub_9a57 {
  strings:
    $key_9a57 = { ce 3f [2] ba 27 [2] fd 25 [2] ba 34 [2] f4 38 [2] f8 32 [2] ef 39 [2] f4 77 [2] c9 }

  condition:
    any of them
}