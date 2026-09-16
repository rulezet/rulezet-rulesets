rule TTP_XOR_MULT_DOSStub_d967 {
  strings:
    $key_d967 = { 8d 0f [2] f9 17 [2] be 15 [2] f9 04 [2] b7 08 [2] bb 02 [2] ac 09 [2] b7 47 [2] 8a }

  condition:
    any of them
}