rule TTP_XOR_MULT_DOSStub_d920 {
  strings:
    $key_d920 = { 8d 48 [2] f9 50 [2] be 52 [2] f9 43 [2] b7 4f [2] bb 45 [2] ac 4e [2] b7 00 [2] 8a }

  condition:
    any of them
}