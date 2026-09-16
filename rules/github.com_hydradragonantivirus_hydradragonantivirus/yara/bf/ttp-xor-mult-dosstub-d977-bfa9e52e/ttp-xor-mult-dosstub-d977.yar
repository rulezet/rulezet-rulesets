rule TTP_XOR_MULT_DOSStub_d977 {
  strings:
    $key_d977 = { 8d 1f [2] f9 07 [2] be 05 [2] f9 14 [2] b7 18 [2] bb 12 [2] ac 19 [2] b7 57 [2] 8a }

  condition:
    any of them
}