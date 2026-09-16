rule TTP_XOR_MULT_DOSStub_d9f7 {
  strings:
    $key_d9f7 = { 8d 9f [2] f9 87 [2] be 85 [2] f9 94 [2] b7 98 [2] bb 92 [2] ac 99 [2] b7 d7 [2] 8a }

  condition:
    any of them
}