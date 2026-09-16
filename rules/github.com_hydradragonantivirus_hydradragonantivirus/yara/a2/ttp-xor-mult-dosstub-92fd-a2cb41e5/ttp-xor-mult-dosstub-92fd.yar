rule TTP_XOR_MULT_DOSStub_92fd {
  strings:
    $key_92fd = { c6 95 [2] b2 8d [2] f5 8f [2] b2 9e [2] fc 92 [2] f0 98 [2] e7 93 [2] fc dd [2] c1 }

  condition:
    any of them
}