rule TTP_XOR_MULT_DOSStub_9a99 {
  strings:
    $key_9a99 = { ce f1 [2] ba e9 [2] fd eb [2] ba fa [2] f4 f6 [2] f8 fc [2] ef f7 [2] f4 b9 [2] c9 }

  condition:
    any of them
}