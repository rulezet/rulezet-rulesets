rule TTP_XOR_MULT_DOSStub_d926 {
  strings:
    $key_d926 = { 8d 4e [2] f9 56 [2] be 54 [2] f9 45 [2] b7 49 [2] bb 43 [2] ac 48 [2] b7 06 [2] 8a }

  condition:
    any of them
}