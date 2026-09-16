rule TTP_XOR_MULT_DOSStub_d960 {
  strings:
    $key_d960 = { 8d 08 [2] f9 10 [2] be 12 [2] f9 03 [2] b7 0f [2] bb 05 [2] ac 0e [2] b7 40 [2] 8a }

  condition:
    any of them
}