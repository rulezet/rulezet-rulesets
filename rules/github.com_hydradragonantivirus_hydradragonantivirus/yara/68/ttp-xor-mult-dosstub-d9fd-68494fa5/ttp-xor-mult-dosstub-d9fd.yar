rule TTP_XOR_MULT_DOSStub_d9fd {
  strings:
    $key_d9fd = { 8d 95 [2] f9 8d [2] be 8f [2] f9 9e [2] b7 92 [2] bb 98 [2] ac 93 [2] b7 dd [2] 8a }

  condition:
    any of them
}