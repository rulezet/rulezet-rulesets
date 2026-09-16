rule TTP_XOR_MULT_DOSStub_d970 {
  strings:
    $key_d970 = { 8d 18 [2] f9 00 [2] be 02 [2] f9 13 [2] b7 1f [2] bb 15 [2] ac 1e [2] b7 50 [2] 8a }

  condition:
    any of them
}