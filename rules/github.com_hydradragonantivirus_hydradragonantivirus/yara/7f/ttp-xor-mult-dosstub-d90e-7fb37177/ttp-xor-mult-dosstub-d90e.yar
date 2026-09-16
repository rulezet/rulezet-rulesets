rule TTP_XOR_MULT_DOSStub_d90e {
  strings:
    $key_d90e = { 8d 66 [2] f9 7e [2] be 7c [2] f9 6d [2] b7 61 [2] bb 6b [2] ac 60 [2] b7 2e [2] 8a }

  condition:
    any of them
}