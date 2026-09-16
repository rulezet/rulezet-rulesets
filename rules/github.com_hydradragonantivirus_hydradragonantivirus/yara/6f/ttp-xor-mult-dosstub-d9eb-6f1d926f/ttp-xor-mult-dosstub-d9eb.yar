rule TTP_XOR_MULT_DOSStub_d9eb {
  strings:
    $key_d9eb = { 8d 83 [2] f9 9b [2] be 99 [2] f9 88 [2] b7 84 [2] bb 8e [2] ac 85 [2] b7 cb [2] 8a }

  condition:
    any of them
}