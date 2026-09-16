rule TTP_XOR_MULT_DOSStub_d94b {
  strings:
    $key_d94b = { 8d 23 [2] f9 3b [2] be 39 [2] f9 28 [2] b7 24 [2] bb 2e [2] ac 25 [2] b7 6b [2] 8a }

  condition:
    any of them
}