rule TTP_XOR_MULT_DOSStub_d910 {
  strings:
    $key_d910 = { 8d 78 [2] f9 60 [2] be 62 [2] f9 73 [2] b7 7f [2] bb 75 [2] ac 7e [2] b7 30 [2] 8a }

  condition:
    any of them
}