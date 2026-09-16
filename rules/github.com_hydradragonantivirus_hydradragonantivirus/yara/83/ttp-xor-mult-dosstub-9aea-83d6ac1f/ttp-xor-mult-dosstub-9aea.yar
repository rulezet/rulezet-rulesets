rule TTP_XOR_MULT_DOSStub_9aea {
  strings:
    $key_9aea = { ce 82 [2] ba 9a [2] fd 98 [2] ba 89 [2] f4 85 [2] f8 8f [2] ef 84 [2] f4 ca [2] c9 }

  condition:
    any of them
}