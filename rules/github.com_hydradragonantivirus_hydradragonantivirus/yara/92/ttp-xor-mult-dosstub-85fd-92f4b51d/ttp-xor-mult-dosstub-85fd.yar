rule TTP_XOR_MULT_DOSStub_85fd {
  strings:
    $key_85fd = { d1 95 [2] a5 8d [2] e2 8f [2] a5 9e [2] eb 92 [2] e7 98 [2] f0 93 [2] eb dd [2] d6 }

  condition:
    any of them
}