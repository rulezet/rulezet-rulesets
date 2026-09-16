rule TTP_XOR_MULT_DOSStub_d907 {
  strings:
    $key_d907 = { 8d 6f [2] f9 77 [2] be 75 [2] f9 64 [2] b7 68 [2] bb 62 [2] ac 69 [2] b7 27 [2] 8a }

  condition:
    any of them
}