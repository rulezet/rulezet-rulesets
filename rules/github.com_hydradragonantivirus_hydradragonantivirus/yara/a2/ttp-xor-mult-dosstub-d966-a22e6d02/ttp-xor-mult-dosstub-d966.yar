rule TTP_XOR_MULT_DOSStub_d966 {
  strings:
    $key_d966 = { 8d 0e [2] f9 16 [2] be 14 [2] f9 05 [2] b7 09 [2] bb 03 [2] ac 08 [2] b7 46 [2] 8a }

  condition:
    any of them
}