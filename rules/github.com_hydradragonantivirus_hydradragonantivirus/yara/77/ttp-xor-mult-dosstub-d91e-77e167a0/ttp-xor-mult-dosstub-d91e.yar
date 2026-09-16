rule TTP_XOR_MULT_DOSStub_d91e {
  strings:
    $key_d91e = { 8d 76 [2] f9 6e [2] be 6c [2] f9 7d [2] b7 71 [2] bb 7b [2] ac 70 [2] b7 3e [2] 8a }

  condition:
    any of them
}