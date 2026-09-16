rule TTP_XOR_MULT_DOSStub_d965 {
  strings:
    $key_d965 = { 8d 0d [2] f9 15 [2] be 17 [2] f9 06 [2] b7 0a [2] bb 00 [2] ac 0b [2] b7 45 [2] 8a }

  condition:
    any of them
}