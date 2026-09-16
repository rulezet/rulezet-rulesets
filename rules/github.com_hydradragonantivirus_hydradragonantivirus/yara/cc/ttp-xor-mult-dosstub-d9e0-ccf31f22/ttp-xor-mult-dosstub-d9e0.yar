rule TTP_XOR_MULT_DOSStub_d9e0 {
  strings:
    $key_d9e0 = { 8d 88 [2] f9 90 [2] be 92 [2] f9 83 [2] b7 8f [2] bb 85 [2] ac 8e [2] b7 c0 [2] 8a }

  condition:
    any of them
}