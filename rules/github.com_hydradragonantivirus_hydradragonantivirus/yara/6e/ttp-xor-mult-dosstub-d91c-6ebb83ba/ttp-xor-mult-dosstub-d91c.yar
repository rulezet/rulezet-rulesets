rule TTP_XOR_MULT_DOSStub_d91c {
  strings:
    $key_d91c = { 8d 74 [2] f9 6c [2] be 6e [2] f9 7f [2] b7 73 [2] bb 79 [2] ac 72 [2] b7 3c [2] 8a }

  condition:
    any of them
}